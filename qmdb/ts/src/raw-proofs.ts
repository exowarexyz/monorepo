// Copies of the qmdb services whose responses declare each proof as `bytes`
// instead of a message.
//
// A message field and a `bytes` field are encoded the same way on the wire (a
// tag, a length, then the bytes), so these copies read the same responses as
// the generated services. What changes is what protobuf-es does with them. The
// generated services decode every proof into a tree of JS objects, which the
// client then had to encode back into the same bytes to hand them to wasm.
// These copies return each proof as a view into the response body, and that
// view goes to wasm as is.
//
// This only works in binary format. In JSON a proof is a JSON object, not
// base64 text, so the qmdb clients always use binary.
import { clone, createFileRegistry, type DescFile, type DescService, type Message } from '@bufbuild/protobuf';
import type { GenMessage, GenService } from '@bufbuild/protobuf/codegenv1';
import { FieldDescriptorProto_Type, FileDescriptorProtoSchema } from '@bufbuild/protobuf/wkt';
import {
  CurrentOperationService,
  GetCurrentOperationRangeRequestSchema,
} from './generated/proto/qmdb/v1/current_operation_pb.js';
import {
  GetManyRequestSchema,
  GetRequestSchema,
  KeyLookupService,
} from './generated/proto/qmdb/v1/key_lookup_pb.js';
import { GetRangeRequestSchema, OrderedKeyRangeService } from './generated/proto/qmdb/v1/key_range_pb.js';
import {
  GetOperationRangeRequestSchema,
  GetOperationsRequestSchema,
  OperationLogService,
  SubscribeRequestSchema,
} from './generated/proto/qmdb/v1/operation_log_pb.js';

/**
 * Rebuild `service` from its file descriptor, with the named fields of the
 * named response messages changed from message fields to `bytes` fields.
 * Throws if a named message or field is missing or is not a message field, so a
 * proto change can't silently leave a proof decoded as objects.
 */
function rawService<S extends DescService>(
  service: DescService,
  fields: Readonly<Record<string, readonly string[]>>,
): S {
  const file = clone(FileDescriptorProtoSchema, service.file.proto);
  for (const [messageName, fieldNames] of Object.entries(fields)) {
    const message = file.messageType.find(({ name }) => name === messageName);
    for (const fieldName of fieldNames) {
      const field = message?.field.find(({ name }) => name === fieldName);
      if (field?.type !== FieldDescriptorProto_Type.MESSAGE) {
        throw new Error(`qmdb ${messageName}.${fieldName} is not a message field`);
      }
      field.type = FieldDescriptorProto_Type.BYTES;
      field.typeName = '';
    }
  }
  const imports = new Map<string, DescFile>();
  const collect = (from: DescFile) => {
    for (const dependency of from.dependencies) {
      imports.set(dependency.proto.name, dependency);
      collect(dependency);
    }
  };
  collect(service.file);
  const registry = createFileRegistry(file, (name) => imports.get(name));
  return registry.getService(service.typeName) as S;
}

/** A response whose proof arrives as its encoded bytes. */
type ProofBytes<TypeName extends string> = GenMessage<Message<TypeName> & { proof: Uint8Array }>;

export const RawOperationLogService: GenService<{
  getOperationRange: {
    methodKind: 'unary';
    input: typeof GetOperationRangeRequestSchema;
    output: ProofBytes<'qmdb.v1.GetOperationRangeResponse'>;
  };
  getOperations: {
    methodKind: 'unary';
    input: typeof GetOperationsRequestSchema;
    output: ProofBytes<'qmdb.v1.GetOperationsResponse'>;
  };
  subscribe: {
    methodKind: 'server_streaming';
    input: typeof SubscribeRequestSchema;
    output: GenMessage<
      Message<'qmdb.v1.SubscribeResponse'> & { resumeSequenceNumber: bigint; proof: Uint8Array }
    >;
  };
}> = rawService(OperationLogService, {
  GetOperationRangeResponse: ['proof'],
  GetOperationsResponse: ['proof'],
  SubscribeResponse: ['proof'],
});

export const RawKeyLookupService: GenService<{
  get: {
    methodKind: 'unary';
    input: typeof GetRequestSchema;
    output: ProofBytes<'qmdb.v1.GetResponse'>;
  };
  getMany: {
    methodKind: 'unary';
    input: typeof GetManyRequestSchema;
    output: GenMessage<Message<'qmdb.v1.GetManyResponse'> & { results: Uint8Array[] }>;
  };
}> = rawService(KeyLookupService, {
  GetResponse: ['proof'],
  GetManyResponse: ['results'],
});

export const RawOrderedKeyRangeService: GenService<{
  getRange: {
    methodKind: 'unary';
    input: typeof GetRangeRequestSchema;
    output: GenMessage<
      Message<'qmdb.v1.GetRangeResponse'> & { entries: Uint8Array[]; startProof?: Uint8Array }
    >;
  };
}> = rawService(OrderedKeyRangeService, {
  GetRangeResponse: ['entries', 'start_proof'],
});

export const RawCurrentOperationService: GenService<{
  getCurrentOperationRange: {
    methodKind: 'unary';
    input: typeof GetCurrentOperationRangeRequestSchema;
    output: ProofBytes<'qmdb.v1.GetCurrentOperationRangeResponse'>;
  };
}> = rawService(CurrentOperationService, {
  GetCurrentOperationRangeResponse: ['proof'],
});
