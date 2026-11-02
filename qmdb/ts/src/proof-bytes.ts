// Copies of the qmdb services whose responses declare each proof as `repeated
// bytes` instead of a message.
//
// A message field and a `bytes` field are encoded the same way on the wire (a
// tag, a length, then the bytes), so these copies read the same responses as
// the generated services. What changes is what protobuf-es does with them. The
// generated services decode every proof into a tree of JS objects, which the
// client then had to encode back into the same bytes to hand them to wasm.
// These copies return each proof as a view into the response body, and the
// client passes that view to wasm without copying it in JS.
//
// This only works in binary format. In JSON a proof is a JSON object, not
// base64 text, so the qmdb clients always use binary.
//
// A proof field declared once can still appear several times in a response.
// Protobuf parses the occurrences as one message, merged in order, which is the
// same as parsing their bytes joined end to end. So a singular proof field
// becomes `repeated bytes` too, which keeps every occurrence, and the client
// joins them before calling wasm. A response from the qmdb server has one
// occurrence.
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

type Methods<S> = S extends GenService<infer M> ? M : never;
type Output<Method> = Method extends { output: GenMessage<infer M> } ? M : never;

/**
 * The TypeScript names of the message fields of `M`, singular or repeated.
 * protobuf-es nests a oneof's members under the oneof's name, so they never
 * appear here.
 */
type MessageFields<M> = {
  [K in keyof M]-?: NonNullable<M[K]> extends Message | Message[] ? K : never;
}[keyof M];

/**
 * For each method of service `S`, the response fields to retype. A method `S`
 * doesn't have, or a field that isn't a message field, is a type error.
 */
type Fields<S, F> = {
  [M in keyof F]: M extends keyof Methods<S> ? readonly MessageFields<Output<Methods<S>[M]>>[] : never;
};

/**
 * Message `M` with the fields `K` holding their encoded bytes: one entry per
 * occurrence on the wire, or per element of a repeated field.
 */
type ProofBytesMessage<M extends Message, K extends PropertyKey> = Message<M['$typeName']> &
  Omit<M, K> & { [P in K & keyof M]: Uint8Array[] };

/** Service `S` with the outputs of the methods in `F` retyped. */
type ProofBytesService<S, F> = GenService<{
  [M in keyof Methods<S>]: M extends keyof F
    ? Omit<Methods<S>[M], 'output'> & {
        output: GenMessage<ProofBytesMessage<Output<Methods<S>[M]>, F[M] extends readonly (infer K extends PropertyKey)[] ? K : never>>;
      }
    : Methods<S>[M];
}>;

/**
 * Rebuild `service` from its file descriptor, with the named response fields
 * changed from message fields to `repeated bytes` fields. `Fields` already
 * limits `fields` to message fields, so this only throws if a response isn't a
 * top-level message of the service's file, where the lookup below can't find it.
 */
function proofBytesService<S extends GenService<GenServiceMethods>, const F extends Fields<S, F>>(
  service: S,
  fields: F,
): ProofBytesService<S, F> {
  const file = clone(FileDescriptorProtoSchema, service.file.proto);
  for (const [methodName, fieldNames] of Object.entries(fields as Record<string, readonly string[]>)) {
    const output = (service as DescService).method[methodName]?.output;
    if (output?.file !== service.file || output.parent !== undefined) {
      throw new Error(`qmdb ${service.name}.${methodName} has no top-level response in ${service.file.name}`);
    }
    const message = file.messageType.find(({ name }) => name === output.name);
    for (const fieldName of fieldNames) {
      const name = output.field[fieldName]?.name;
      const field = message?.field.find((field) => field.name === name);
      if (field?.type !== FieldDescriptorProto_Type.MESSAGE) {
        throw new Error(`qmdb ${output.name}.${fieldName} is not a message field`);
      }
      field.type = FieldDescriptorProto_Type.BYTES;
      field.typeName = '';
      field.label = FieldDescriptorProto_Label.REPEATED;
      // A repeated field can't be `optional` or in a oneof. protobuf-es ignores
      // both for a repeated field anyway, but this keeps the descriptor valid.
      field.proto3Optional = false;
      clearField(field, FieldDescriptorProtoSchema.field.oneofIndex);
    }
  }
  // The registry also adds the imports of each file it resolves, so resolving
  // direct imports is enough.
  const registry = createFileRegistry(file, (name) =>
    service.file.dependencies.find((dependency) => dependency.proto.name === name));
  return registry.getService(service.typeName) as ProofBytesService<S, F>;
}

export const ProofBytesOperationLogService = /*@__PURE__*/ proofBytesService(OperationLogService, {
  getOperationRange: ['proof'],
  getOperations: ['proof'],
  subscribe: ['proof'],
});

export const ProofBytesKeyLookupService = /*@__PURE__*/ proofBytesService(KeyLookupService, {
  get: ['proof'],
  getMany: ['results'],
});

export const ProofBytesOrderedKeyRangeService = /*@__PURE__*/ proofBytesService(OrderedKeyRangeService, {
  getRange: ['entries', 'startProof'],
});

export const ProofBytesCurrentOperationService = /*@__PURE__*/ proofBytesService(CurrentOperationService, {
  getCurrentOperationRange: ['proof'],
});
