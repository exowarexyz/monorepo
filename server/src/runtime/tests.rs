use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::serve::Listener;
use buffa::Message as _;
use bytes::Bytes;
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use http_body_util::{BodyExt, Full};
use hyper::rt::Timer as _;
use hyper_util::rt::TokioIo;

use super::{simulated, testing::SimulatedRuntime, Deadline, Executor, Runtime, TaskSet, Timer};
use crate::{
    ingest::{transport::serve, DecodeBuffers, PutConfig},
    Ingest, IngestState, PutError, PutInput,
};

struct Accept;

impl Ingest for Accept {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        let mut entries = 0;
        while let Some(batch) = input.next_batch(DecodeBuffers::default()).await? {
            entries += batch.entries().count();
        }
        input.finish().await?;
        Ok(entries as u64)
    }
}

fn request(compressed: bool) -> http::Request<Full<Bytes>> {
    let message = exoware_sdk::ingest::PutRequest {
        kvs: vec![crate::Entry {
            key: b"key".to_vec(),
            value: Bytes::from_static(b"value"),
            ..Default::default()
        }],
        ..Default::default()
    };
    let bytes = message.encode_to_vec();
    let bytes = if compressed {
        zstd::bulk::compress(&bytes, 1).unwrap()
    } else {
        bytes
    };
    http::Request::post("http://store.test/log.ingest.v1.Service/Put")
        .header("content-type", "application/proto")
        .header(
            "content-encoding",
            if compressed { "zstd" } else { "identity" },
        )
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

async fn check_response(response: http::Response<hyper::body::Incoming>) -> Vec<u8> {
    assert_eq!(response.status(), http::StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        exoware_sdk::ingest::PutResponse::decode_from_slice(&bytes)
            .unwrap()
            .sequence_number,
        1
    );
    bytes.to_vec()
}

fn scenario(seed: u64, http2: bool) -> Vec<Vec<u8>> {
    deterministic::Runner::new(
        deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30))),
    )
    .start(|context| async move {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let runtime: Arc<dyn Runtime> = Arc::new(SimulatedRuntime(context.child("http")));
        let network = simulated::SimulatedNetwork::new(64);
        let listener = network.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();
        let config = PutConfig::default();
        let budget = config.budget.clone();
        let service = crate::ingest_service(
            IngestState::new(runtime.clone(), Arc::new(Accept)).with_put_config(config),
        );
        let server = runtime.spawn(
            "server",
            Box::new(move |runtime| {
                Box::pin(async move {
                    serve(runtime, listener, service, std::future::pending())
                        .await
                        .unwrap();
                })
            }),
        );
        let io = network.connect(address).await.unwrap();
        io.control().fragment(7, 11);
        let tasks = TaskSet::default();
        let mut outcomes = Vec::new();
        if http2 {
            let mut builder = hyper::client::conn::http2::Builder::new(Executor::new(
                runtime.clone(),
                tasks.spawner(),
            ));
            builder.timer(Timer::new(runtime.clock()));
            let (mut sender, connection) = builder.handshake(TokioIo::new(io)).await.unwrap();
            let driver = runtime.spawn(
                "client",
                Box::new(move |_| {
                    Box::pin(async move {
                        let _ = connection.await;
                    })
                }),
            );
            for compressed in [false, true] {
                outcomes.push(
                    check_response(sender.send_request(request(compressed)).await.unwrap()).await,
                );
            }
            drop(sender);
            drop(driver);
        } else {
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
                .await
                .unwrap();
            let driver = runtime.spawn(
                "client",
                Box::new(move |_| {
                    Box::pin(async move {
                        let _ = connection.await;
                    })
                }),
            );
            for compressed in [false, true] {
                sender.ready().await.unwrap();
                outcomes.push(
                    check_response(sender.send_request(request(compressed)).await.unwrap()).await,
                );
            }
            drop(sender);
            drop(driver);
        }
        drop(tasks);
        drop(server);
        Deadline::after(runtime.clock(), Duration::from_millis(10))
            .wait()
            .await;
        assert_eq!(budget.usage(), (0, 0));
        assert!(
            network.connect(address).await.is_err(),
            "aborting the server must drop its listener"
        );
        assert!(tokio::runtime::Handle::try_current().is_err());
        outcomes
    })
}

#[test]
fn http_ingestion_replays_without_tokio() {
    for seed in 0..32 {
        for http2 in [false, true] {
            assert_eq!(scenario(seed, http2), scenario(seed, http2));
        }
    }
}

#[test]
fn hyper_timer_uses_simulated_time_and_reset() {
    deterministic::Runner::default().start(|context| async move {
        let runtime = SimulatedRuntime(context.child("timer"));
        let timer = Timer::new(runtime.clock());
        let start = timer.now();
        let mut sleep = timer.sleep(Duration::from_secs(60));
        timer.reset(&mut sleep, start + Duration::from_secs(2));
        sleep.await;
        let elapsed = timer.now() - start;
        assert!(elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(3));
    });
}

#[test]
fn dropping_a_task_cancels_its_work() {
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    deterministic::Runner::default().start(|context| async move {
        let runtime = SimulatedRuntime(context.child("tasks"));
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let task = runtime.spawn(
            "pending",
            Box::new(move |_| {
                Box::pin(async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                })
            }),
        );
        drop(task);
        Deadline::after(runtime.clock(), Duration::from_millis(10))
            .wait()
            .await;
        assert!(dropped.load(Ordering::SeqCst));
    });
}

#[test]
fn simulated_streams_preserve_backpressure_and_half_close() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    deterministic::Runner::default().start(|_| async move {
        let network = simulated::SimulatedNetwork::new(2);
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client = network
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await;
        client.write_all(b"ab").await.unwrap();
        assert!(futures::poll!(std::pin::pin!(client.write(b"c"))).is_pending());
        let mut bytes = [0; 2];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ab");
        client.shutdown().await.unwrap();
        assert_eq!(server.read(&mut bytes).await.unwrap(), 0);
        server.write_all(b"ok").await.unwrap();
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        assert!(futures::poll!(std::pin::pin!(client.read(&mut bytes))).is_pending());
        client.control().reset();
        assert_eq!(
            client.read(&mut bytes).await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            server.write(b"x").await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
    });
}

#[test]
fn rejected_http2_streams_expire_while_response_flow_control_is_blocked() {
    use crate::ingest::{BudgetConfig, IngestBudget};
    use axum::body::Body;
    use tower::ServiceExt as _;

    for seed in 0..32 {
        for window in [0, 1] {
            deterministic::Runner::new(
                deterministic::Config::default()
                    .with_seed(seed)
                    .with_timeout(Some(Duration::from_secs(10))),
            )
            .start(|context| async move {
                let runtime: Arc<dyn Runtime> = Arc::new(SimulatedRuntime(context.child("http")));
                let network = simulated::SimulatedNetwork::new(64);
                let listener = network.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                let address = listener.local_addr().unwrap();
                let budget = IngestBudget::new(BudgetConfig {
                    max_requests: 1,
                    max_bytes: 1024,
                });
                let held = budget.try_admit(1).unwrap();
                let service = crate::ingest_service(
                    IngestState::new(runtime.clone(), Arc::new(Accept)).with_put_config(
                        PutConfig {
                            budget: budget.clone(),
                            timeout: Duration::from_secs(2),
                            max_wire_bytes: 1024,
                            ..Default::default()
                        },
                    ),
                );
                let service = tower::service_fn(move |request: http::Request<Body>| {
                    let service = service.clone();
                    async move {
                        if request.uri().path() == "/health" {
                            return Ok(http::Response::new(Body::empty()));
                        }
                        service.oneshot(request).await
                    }
                });
                let server = runtime.spawn(
                    "server",
                    Box::new(move |runtime| {
                        Box::pin(async move {
                            serve(runtime, listener, service, std::future::pending())
                                .await
                                .unwrap();
                        })
                    }),
                );
                let (mut connection, driver) = h2::client::Builder::new()
                    .initial_window_size(window)
                    .handshake::<_, Bytes>(network.connect(address).await.unwrap())
                    .await
                    .unwrap();
                let driver = runtime.spawn(
                    "client",
                    Box::new(move |_| {
                        Box::pin(async move {
                            let _ = driver.await;
                        })
                    }),
                );
                let deadline = Deadline::after(runtime.clock(), Duration::from_secs(3));
                let (response, mut upload) = connection
                    .send_request(
                        http::Request::post(format!("http://{address}/log.ingest.v1.Service/Put"))
                            .header("content-type", "application/proto")
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                let response = deadline.timeout(response).await.unwrap().unwrap();
                assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
                assert!(!response.body().is_end_stream());
                let reset = deadline
                    .timeout(std::future::poll_fn(|cx| upload.poll_reset(cx)))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reset, h2::Reason::CANCEL);
                let (health, _) = connection
                    .send_request(
                        http::Request::get(format!("http://{address}/health"))
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
                assert_eq!(
                    deadline.timeout(health).await.unwrap().unwrap().status(),
                    http::StatusCode::OK
                );
                drop(held);
                drop(response);
                drop(connection);
                drop(driver);
                drop(server);
                Deadline::after(runtime.clock(), Duration::from_millis(10))
                    .wait()
                    .await;
                assert_eq!(budget.usage(), (0, 0));
            });
        }
    }
}

#[test]
fn http1_watchdog_expires_with_blocked_output_and_ignores_stale_requests() {
    use crate::ingest::transport::ConnectionControl;
    use axum::body::Body;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct BlockedOutput(simulated::SimulatedListener);
    impl Listener for BlockedOutput {
        type Io = simulated::SimulatedIo;
        type Addr = std::net::SocketAddr;

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            let (io, address) = self.0.accept().await;
            io.control().block_writes(true);
            (io, address)
        }

        fn local_addr(&self) -> std::io::Result<Self::Addr> {
            self.0.local_addr()
        }
    }

    for seed in 0..32 {
        deterministic::Runner::new(deterministic::Config::default().with_seed(seed)).start(
            |context| async move {
                let runtime: Arc<dyn Runtime> = Arc::new(SimulatedRuntime(context.child("http")));
                let network = simulated::SimulatedNetwork::new(64);
                let listener = network.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                let address = listener.local_addr().unwrap();
                let clock = runtime.clock();
                let service = tower::service_fn(move |request: http::Request<Body>| {
                    let control = request.extensions().get::<ConnectionControl>().unwrap();
                    let old = control
                        .arm_http1(
                            request.version(),
                            Deadline::after(clock.clone(), Duration::from_millis(10)),
                        )
                        .unwrap();
                    control
                        .arm_http1(
                            request.version(),
                            Deadline::after(clock.clone(), Duration::from_millis(100)),
                        )
                        .unwrap();
                    assert!(!control.expire(old));
                    assert!(!control.disarm(old));
                    std::future::ready(Ok::<_, std::convert::Infallible>(http::Response::new(
                        Body::from("response must not reach the client"),
                    )))
                });
                let server = runtime.spawn(
                    "server",
                    Box::new(move |runtime| {
                        Box::pin(async move {
                            serve(
                                runtime,
                                BlockedOutput(listener),
                                service,
                                std::future::pending(),
                            )
                            .await
                            .unwrap();
                        })
                    }),
                );
                let mut client = network.connect(address).await.unwrap();
                let start = runtime.clock().now();
                client
                    .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx")
                    .await
                    .unwrap();
                let mut response = Vec::new();
                Deadline::after(runtime.clock(), Duration::from_secs(1))
                    .timeout(client.read_to_end(&mut response))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(response.is_empty());
                assert!(runtime.clock().elapsed(start) >= Duration::from_millis(100));
                drop(server);
            },
        );
    }
}

struct PausedBackend {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl Ingest for PausedBackend {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        let count = Accept.put(input).await?;
        self.started.notify_one();
        self.release.notified().await;
        Ok(count)
    }
}

#[test]
fn graceful_shutdown_drains_a_completed_upload_before_stopping() {
    deterministic::Runner::default().start(|context| async move {
        let runtime: Arc<dyn Runtime> = Arc::new(SimulatedRuntime(context.child("http")));
        let network = simulated::SimulatedNetwork::new(64);
        let listener = network.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();
        let backend = Arc::new(PausedBackend {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let service = crate::ingest_service(IngestState::new(runtime.clone(), backend.clone()));
        let (stop, stopped) = futures::channel::oneshot::channel();
        let mut server = runtime.spawn(
            "server",
            Box::new(move |runtime| {
                Box::pin(async move {
                    serve(runtime, listener, service, async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
                })
            }),
        );
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(
            network.connect(address).await.unwrap(),
        ))
        .await
        .unwrap();
        let driver = runtime.spawn(
            "client",
            Box::new(move |_| {
                Box::pin(async move {
                    let _ = connection.await;
                })
            }),
        );
        let (reply, response) = futures::channel::oneshot::channel();
        let request = runtime.spawn(
            "request",
            Box::new(move |_| {
                Box::pin(async move {
                    let _ = reply.send(sender.send_request(request(false)).await);
                })
            }),
        );
        backend.started.notified().await;
        stop.send(()).unwrap();
        Deadline::after(runtime.clock(), Duration::from_millis(10))
            .wait()
            .await;
        assert!(network.connect(address).await.is_err());
        assert!(futures::poll!(&mut server).is_pending());
        backend.release.notify_one();
        check_response(response.await.unwrap().unwrap()).await;
        server.await.unwrap();
        request.await.unwrap();
        drop(driver);
    });
}

#[tokio::test]
async fn abandoned_cpu_work_keeps_its_captures_until_completion() {
    use super::{run_cpu, TokioRuntime};
    let runtime = TokioRuntime::current();
    let (started, running) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let owned = Arc::new(());
    let retained = owned.clone();
    let future = run_cpu(runtime.clone(), move || {
        let _retained = retained;
        started.send(()).unwrap();
        released.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    let mut future = Box::pin(future);
    assert!(futures::poll!(&mut future).is_pending());
    running.await.unwrap();
    drop(future);
    assert_eq!(Arc::strong_count(&owned), 2);
    release.send(()).unwrap();
    Deadline::after(runtime.clock(), Duration::from_secs(5))
        .timeout(async {
            while Arc::strong_count(&owned) != 1 {
                super::yield_now().await;
            }
        })
        .await
        .unwrap();
    assert!(run_cpu(runtime, || panic!("CPU panic")).await.is_err());
}
