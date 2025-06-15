# exoware-sandbox

This example provides a basic web interface to interact with the Exoware API. It demonstrates how to use the `exoware-sdk` to connect to and interact with the `store` and `stream` modules of the simulator.

## Prerequisites

- Node.js and npm
- Rust and Cargo

## How to Run

1.  **Start the Simulator:**

    Open a terminal in the root of the monorepo and run the following command to start the simulator. You can choose any auth token.

    ```bash
    cargo run --package exoware-simulator -- --verbose server run --token your-secret-token
    ```

    _If you opt to use a different token, you must update the `VITE_TOKEN` environment variable in the `examples/sandbox/.env.local` file._

2.  **Install Dependencies and Run the Web App:**

    Navigate to the `examples/sandbox` directory and install the dependencies, then start the development server. `npm install` will also automatically build the TypeScript SDK.

    ```bash
    # from the root of the monorepo
    cd examples/website
    npm install
    npm run dev
    ```

3.  **Open the Web UI:**

    Open your browser and navigate to the URL provided by Vite (usually `http://localhost:5173`). You should see the UI for interacting with the simulator.

## Features

-   **Store:**
    -   Set a key-value pair.
    -   Get a value by key.
    -   Query for a range of keys.
-   **Stream:**
    -   Publish messages to a named stream.
    -   Subscribe to a named stream and see messages in real-time.
