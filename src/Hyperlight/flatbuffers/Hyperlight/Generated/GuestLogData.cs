// <auto-generated>
//  automatically generated by the FlatBuffers compiler, do not modify
// </auto-generated>

namespace Hyperlight.Generated
{

using global::System;
using global::System.Collections.Generic;
using global::Google.FlatBuffers;

public struct GuestLogData : IFlatbufferObject
{
  private Table __p;
  public ByteBuffer ByteBuffer { get { return __p.bb; } }
  public static void ValidateVersion() { FlatBufferConstants.FLATBUFFERS_23_5_26(); }
  public static GuestLogData GetRootAsGuestLogData(ByteBuffer _bb) { return GetRootAsGuestLogData(_bb, new GuestLogData()); }
  public static GuestLogData GetRootAsGuestLogData(ByteBuffer _bb, GuestLogData obj) { return (obj.__assign(_bb.GetInt(_bb.Position) + _bb.Position, _bb)); }
  public static bool VerifyGuestLogData(ByteBuffer _bb) {Google.FlatBuffers.Verifier verifier = new Google.FlatBuffers.Verifier(_bb); return verifier.VerifyBuffer("", false, GuestLogDataVerify.Verify); }
  public void __init(int _i, ByteBuffer _bb) { __p = new Table(_i, _bb); }
  public GuestLogData __assign(int _i, ByteBuffer _bb) { __init(_i, _bb); return this; }

  public string Message { get { int o = __p.__offset(4); return o != 0 ? __p.__string(o + __p.bb_pos) : null; } }
#if ENABLE_SPAN_T
  public Span<byte> GetMessageBytes() { return __p.__vector_as_span<byte>(4, 1); }
#else
  public ArraySegment<byte>? GetMessageBytes() { return __p.__vector_as_arraysegment(4); }
#endif
  public byte[] GetMessageArray() { return __p.__vector_as_array<byte>(4); }
  public string Source { get { int o = __p.__offset(6); return o != 0 ? __p.__string(o + __p.bb_pos) : null; } }
#if ENABLE_SPAN_T
  public Span<byte> GetSourceBytes() { return __p.__vector_as_span<byte>(6, 1); }
#else
  public ArraySegment<byte>? GetSourceBytes() { return __p.__vector_as_arraysegment(6); }
#endif
  public byte[] GetSourceArray() { return __p.__vector_as_array<byte>(6); }
  public Hyperlight.Generated.LogLevel Level { get { int o = __p.__offset(8); return o != 0 ? (Hyperlight.Generated.LogLevel)__p.bb.Get(o + __p.bb_pos) : Hyperlight.Generated.LogLevel.Trace; } }
  public string Caller { get { int o = __p.__offset(10); return o != 0 ? __p.__string(o + __p.bb_pos) : null; } }
#if ENABLE_SPAN_T
  public Span<byte> GetCallerBytes() { return __p.__vector_as_span<byte>(10, 1); }
#else
  public ArraySegment<byte>? GetCallerBytes() { return __p.__vector_as_arraysegment(10); }
#endif
  public byte[] GetCallerArray() { return __p.__vector_as_array<byte>(10); }
  public string SourceFile { get { int o = __p.__offset(12); return o != 0 ? __p.__string(o + __p.bb_pos) : null; } }
#if ENABLE_SPAN_T
  public Span<byte> GetSourceFileBytes() { return __p.__vector_as_span<byte>(12, 1); }
#else
  public ArraySegment<byte>? GetSourceFileBytes() { return __p.__vector_as_arraysegment(12); }
#endif
  public byte[] GetSourceFileArray() { return __p.__vector_as_array<byte>(12); }
  public uint Line { get { int o = __p.__offset(14); return o != 0 ? __p.bb.GetUint(o + __p.bb_pos) : (uint)0; } }

  public static Offset<Hyperlight.Generated.GuestLogData> CreateGuestLogData(FlatBufferBuilder builder,
      StringOffset messageOffset = default(StringOffset),
      StringOffset sourceOffset = default(StringOffset),
      Hyperlight.Generated.LogLevel level = Hyperlight.Generated.LogLevel.Trace,
      StringOffset callerOffset = default(StringOffset),
      StringOffset source_fileOffset = default(StringOffset),
      uint line = 0) {
    builder.StartTable(6);
    GuestLogData.AddLine(builder, line);
    GuestLogData.AddSourceFile(builder, source_fileOffset);
    GuestLogData.AddCaller(builder, callerOffset);
    GuestLogData.AddSource(builder, sourceOffset);
    GuestLogData.AddMessage(builder, messageOffset);
    GuestLogData.AddLevel(builder, level);
    return GuestLogData.EndGuestLogData(builder);
  }

  public static void StartGuestLogData(FlatBufferBuilder builder) { builder.StartTable(6); }
  public static void AddMessage(FlatBufferBuilder builder, StringOffset messageOffset) { builder.AddOffset(0, messageOffset.Value, 0); }
  public static void AddSource(FlatBufferBuilder builder, StringOffset sourceOffset) { builder.AddOffset(1, sourceOffset.Value, 0); }
  public static void AddLevel(FlatBufferBuilder builder, Hyperlight.Generated.LogLevel level) { builder.AddByte(2, (byte)level, 0); }
  public static void AddCaller(FlatBufferBuilder builder, StringOffset callerOffset) { builder.AddOffset(3, callerOffset.Value, 0); }
  public static void AddSourceFile(FlatBufferBuilder builder, StringOffset sourceFileOffset) { builder.AddOffset(4, sourceFileOffset.Value, 0); }
  public static void AddLine(FlatBufferBuilder builder, uint line) { builder.AddUint(5, line, 0); }
  public static Offset<Hyperlight.Generated.GuestLogData> EndGuestLogData(FlatBufferBuilder builder) {
    int o = builder.EndTable();
    return new Offset<Hyperlight.Generated.GuestLogData>(o);
  }
  public static void FinishGuestLogDataBuffer(FlatBufferBuilder builder, Offset<Hyperlight.Generated.GuestLogData> offset) { builder.Finish(offset.Value); }
  public static void FinishSizePrefixedGuestLogDataBuffer(FlatBufferBuilder builder, Offset<Hyperlight.Generated.GuestLogData> offset) { builder.FinishSizePrefixed(offset.Value); }
  public GuestLogDataT UnPack() {
    var _o = new GuestLogDataT();
    this.UnPackTo(_o);
    return _o;
  }
  public void UnPackTo(GuestLogDataT _o) {
    _o.Message = this.Message;
    _o.Source = this.Source;
    _o.Level = this.Level;
    _o.Caller = this.Caller;
    _o.SourceFile = this.SourceFile;
    _o.Line = this.Line;
  }
  public static Offset<Hyperlight.Generated.GuestLogData> Pack(FlatBufferBuilder builder, GuestLogDataT _o) {
    if (_o == null) return default(Offset<Hyperlight.Generated.GuestLogData>);
    var _message = _o.Message == null ? default(StringOffset) : builder.CreateString(_o.Message);
    var _source = _o.Source == null ? default(StringOffset) : builder.CreateString(_o.Source);
    var _caller = _o.Caller == null ? default(StringOffset) : builder.CreateString(_o.Caller);
    var _source_file = _o.SourceFile == null ? default(StringOffset) : builder.CreateString(_o.SourceFile);
    return CreateGuestLogData(
      builder,
      _message,
      _source,
      _o.Level,
      _caller,
      _source_file,
      _o.Line);
  }
}

public class GuestLogDataT
{
  public string Message { get; set; }
  public string Source { get; set; }
  public Hyperlight.Generated.LogLevel Level { get; set; }
  public string Caller { get; set; }
  public string SourceFile { get; set; }
  public uint Line { get; set; }

  public GuestLogDataT() {
    this.Message = null;
    this.Source = null;
    this.Level = Hyperlight.Generated.LogLevel.Trace;
    this.Caller = null;
    this.SourceFile = null;
    this.Line = 0;
  }
  public static GuestLogDataT DeserializeFromBinary(byte[] fbBuffer) {
    return GuestLogData.GetRootAsGuestLogData(new ByteBuffer(fbBuffer)).UnPack();
  }
  public byte[] SerializeToBinary() {
    var fbb = new FlatBufferBuilder(0x10000);
    GuestLogData.FinishGuestLogDataBuffer(fbb, GuestLogData.Pack(fbb, this));
    return fbb.DataBuffer.ToSizedArray();
  }
}


static public class GuestLogDataVerify
{
  static public bool Verify(Google.FlatBuffers.Verifier verifier, uint tablePos)
  {
    return verifier.VerifyTableStart(tablePos)
      && verifier.VerifyString(tablePos, 4 /*Message*/, false)
      && verifier.VerifyString(tablePos, 6 /*Source*/, false)
      && verifier.VerifyField(tablePos, 8 /*Level*/, 1 /*Hyperlight.Generated.LogLevel*/, 1, false)
      && verifier.VerifyString(tablePos, 10 /*Caller*/, false)
      && verifier.VerifyString(tablePos, 12 /*SourceFile*/, false)
      && verifier.VerifyField(tablePos, 14 /*Line*/, 4 /*uint*/, 4, false)
      && verifier.VerifyTableEnd(tablePos);
  }
}

}