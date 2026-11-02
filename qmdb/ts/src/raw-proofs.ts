// Copies of the qmdb services whose responses declare each proof as `repeated
// bytes` instead of a message.
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
// A proof field declared once can still appear several times in a response.
// Protobuf parses the occurrences as one message, merged in order, which is the
// same as parsing their bytes joined end to end. So each proof field is
// rewritten as `repeated bytes`, which keeps every occurrence, and the client
// joins them before calling wasm. A response from the qmdb server has one
// occurrence, which goes to wasm without a copy.
//
// These messages keep their generated `$typeName`, so `isMessage` can't tell
// them apart from the generated ones.
import { clearField, clone, createFileRegistry, type DescService, type Message } from '@bufbuild/protobuf';
import type { GenMessage, GenService, GenServiceMethods } from '@bufbuild/protobuf/codegenv1';
import {
  FieldDescriptorProto_Label,
  FieldDescriptorProto_Type,
  FieldDescriptorProtoSchema,
  FileDescriptorProtoSchema,
} from '@bufbuild/protobuf/wkt';
import { CurrentOperationService } from './generated/proto/qmdb/v1/current_operation_pb.js';
import { KeyLookupService } from './generated/proto/qmdb/v1/key_lookup_pb.js';
import { OrderedKeyRangeService } from './generated/proto/qmdb/v1/key_range_pb.js';
import { OperationLogService } from './generated/proto/qmdb/v1/operation_log_pb.js';

/** How a retyped field is declared: plain, `optional` or `repeated`. */
type Kind = 'singular' | 'optional' | 'repeated';

type Methods<S> = S extends GenService<infer M> ? M : never;
type Output<Method> = Method extends { output: GenMessage<infer M> } ? M : never;

/**
 * For each method of service `S`, the response fields to retype, by their
 * TypeScript names. A method or field `S` doesn't have is a type error.
 */
type Fields<S, F> = {
  [M in keyof F]: M extends keyof Methods<S>
    ? { [K in keyof F[M]]: K extends keyof Output<Methods<S>[M]> ? Kind : never }
    : never;
};

/**
 * Message `M` with the fields in `F` holding their encoded bytes, one entry per
 * occurrence on the wire.
 */
type RawMessage<M extends Message, F> = Message<M['$typeName']> &
  Omit<M, keyof F> & { [K in keyof F]: Uint8Array[] };

/** Service `S` with the outputs of the methods in `F` retyped. */
type RawService<S, F> = GenService<{
  [M in keyof Methods<S>]: M extends keyof F
    ? Omit<Methods<S>[M], 'output'> & { output: GenMessage<RawMessage<Output<Methods<S>[M]>, F[M]>> }
    : Methods<S>[M];
}>;

/**
 * Rebuild `service` from its file descriptor, with the named response fields
 * changed from message fields to `repeated bytes` fields. Throws if a named
 * method is missing or a named field is not a message field declared the way
 * `fields` says, so a proto change can't silently leave a proof decoded as
 * objects or typed wrong.
 */
function rawService<S extends GenService<GenServiceMethods>, const F extends Fields<S, F>>(
  service: S,
  fields: F,
): RawService<S, F> {
  const file = clone(FileDescriptorProtoSchema, service.file.proto);
  for (const [methodName, outputFields] of Object.entries(fields as Record<string, Record<string, Kind>>)) {
    const output = (service as DescService).method[methodName]?.output;
    if (output === undefined) {
      throw new Error(`qmdb ${service.name} has no method ${methodName}`);
    }
    const message = file.messageType.find(({ name }) => name === output.name);
    for (const [fieldName, kind] of Object.entries(outputFields)) {
      const name = output.field[fieldName]?.name;
      const field = message?.field.find((field) => field.name === name);
      const declared = field?.label === FieldDescriptorProto_Label.REPEATED
        ? 'repeated'
        : field?.proto3Optional ? 'optional' : 'singular';
      if (field?.type !== FieldDescriptorProto_Type.MESSAGE || declared !== kind) {
        throw new Error(`qmdb ${output.name}.${fieldName} is not a ${kind} message field`);
      }
      field.type = FieldDescriptorProto_Type.BYTES;
      field.typeName = '';
      field.label = FieldDescriptorProto_Label.REPEATED;
      // An `optional` field's synthetic oneof is dropped once no field is in it.
      field.proto3Optional = false;
      clearField(field, FieldDescriptorProtoSchema.field.oneofIndex);
    }
  }
  // The registry also adds the imports of each file it resolves, so resolving
  // direct imports is enough.
  const registry = createFileRegistry(file, (name) =>
    service.file.dependencies.find((dependency) => dependency.proto.name === name));
  return registry.getService(service.typeName) as RawService<S, F>;
}

export const RawOperationLogService = /*@__PURE__*/ rawService(OperationLogService, {
  getOperationRange: { proof: 'singular' },
  getOperations: { proof: 'singular' },
  subscribe: { proof: 'singular' },
});

export const RawKeyLookupService = /*@__PURE__*/ rawService(KeyLookupService, {
  get: { proof: 'singular' },
  getMany: { results: 'repeated' },
});

export const RawOrderedKeyRangeService = /*@__PURE__*/ rawService(OrderedKeyRangeService, {
  getRange: { entries: 'repeated', startProof: 'optional' },
});

export const RawCurrentOperationService = /*@__PURE__*/ rawService(CurrentOperationService, {
  getCurrentOperationRange: { proof: 'singular' },
});
