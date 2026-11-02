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
//
// Two differences from the generated services. If a proof's field appears more
// than once in a response, protobuf merges the parts of a message but keeps only
// the last `bytes` value. No encoder splits a message that way, and wasm rejects
// the partial proof. And these messages keep their generated `$typeName`, so
// `isMessage` can't tell them apart from the generated ones.
import { clone, createFileRegistry, type DescService, type Message } from '@bufbuild/protobuf';
import type { GenMessage, GenService, GenServiceMethods } from '@bufbuild/protobuf/codegenv1';
import { FieldDescriptorProto_Type, FileDescriptorProtoSchema } from '@bufbuild/protobuf/wkt';
import {
  CurrentOperationService,
  type GetCurrentOperationRangeResponse,
} from './generated/proto/qmdb/v1/current_operation_pb.js';
import {
  KeyLookupService,
  type GetManyResponse,
  type GetResponse,
} from './generated/proto/qmdb/v1/key_lookup_pb.js';
import { OrderedKeyRangeService, type GetRangeResponse } from './generated/proto/qmdb/v1/key_range_pb.js';
import {
  OperationLogService,
  type GetOperationRangeResponse,
  type GetOperationsResponse,
  type SubscribeResponse,
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
        throw new Error(`qmdb ${messageName}.${fieldName} is missing or not a message field`);
      }
      field.type = FieldDescriptorProto_Type.BYTES;
      field.typeName = '';
    }
  }
  // The registry also adds the imports of each file it resolves, so resolving
  // direct imports is enough.
  const registry = createFileRegistry(file, (name) =>
    service.file.dependencies.find((dependency) => dependency.proto.name === name));
  return registry.getService(service.typeName) as S;
}

/** Message `M` with the fields in `Fields` retyped. A field `M` lacks is a type error. */
type Raw<M extends Message, Fields extends { [K in keyof Fields]: K extends keyof M ? unknown : never }> =
  Message<M['$typeName']> & Omit<M, keyof Fields> & Fields;

type Methods<S> = S extends GenService<infer M> ? M : never;

/**
 * Generated service type `S`, with the outputs of the methods in `Outputs`
 * replaced. A method `S` lacks is a type error.
 */
type WithOutputs<
  S extends GenService<GenServiceMethods>,
  Outputs extends { [K in keyof Outputs]: K extends keyof Methods<S> ? Message : never },
> = GenService<{
  [K in keyof Methods<S>]: K extends keyof Outputs
    ? Omit<Methods<S>[K], 'output'> & { output: GenMessage<Outputs[K]> }
    : Methods<S>[K];
}>;

export const RawOperationLogService: WithOutputs<typeof OperationLogService, {
  getOperationRange: Raw<GetOperationRangeResponse, { proof: Uint8Array }>;
  getOperations: Raw<GetOperationsResponse, { proof: Uint8Array }>;
  subscribe: Raw<SubscribeResponse, { proof: Uint8Array }>;
}> = /*@__PURE__*/ rawService(OperationLogService, {
  GetOperationRangeResponse: ['proof'],
  GetOperationsResponse: ['proof'],
  SubscribeResponse: ['proof'],
});

export const RawKeyLookupService: WithOutputs<typeof KeyLookupService, {
  get: Raw<GetResponse, { proof: Uint8Array }>;
  getMany: Raw<GetManyResponse, { results: Uint8Array[] }>;
}> = /*@__PURE__*/ rawService(KeyLookupService, {
  GetResponse: ['proof'],
  GetManyResponse: ['results'],
});

export const RawOrderedKeyRangeService: WithOutputs<typeof OrderedKeyRangeService, {
  getRange: Raw<GetRangeResponse, { entries: Uint8Array[]; startProof?: Uint8Array }>;
}> = /*@__PURE__*/ rawService(OrderedKeyRangeService, {
  GetRangeResponse: ['entries', 'start_proof'],
});

export const RawCurrentOperationService: WithOutputs<typeof CurrentOperationService, {
  getCurrentOperationRange: Raw<GetCurrentOperationRangeResponse, { proof: Uint8Array }>;
}> = /*@__PURE__*/ rawService(CurrentOperationService, {
  GetCurrentOperationRangeResponse: ['proof'],
});
