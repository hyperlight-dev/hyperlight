// <auto-generated>
//  automatically generated by the FlatBuffers compiler, do not modify
// </auto-generated>

namespace Hyperlight.Generated
{

using global::System;
using global::System.Collections.Generic;
using global::Google.FlatBuffers;

public struct hlvoid : IFlatbufferObject
{
  private Table __p;
  public ByteBuffer ByteBuffer { get { return __p.bb; } }
  public static void ValidateVersion() { FlatBufferConstants.FLATBUFFERS_23_5_26(); }
  public static hlvoid GetRootAshlvoid(ByteBuffer _bb) { return GetRootAshlvoid(_bb, new hlvoid()); }
  public static hlvoid GetRootAshlvoid(ByteBuffer _bb, hlvoid obj) { return (obj.__assign(_bb.GetInt(_bb.Position) + _bb.Position, _bb)); }
  public void __init(int _i, ByteBuffer _bb) { __p = new Table(_i, _bb); }
  public hlvoid __assign(int _i, ByteBuffer _bb) { __init(_i, _bb); return this; }


  public static void Starthlvoid(FlatBufferBuilder builder) { builder.StartTable(0); }
  public static Offset<Hyperlight.Generated.hlvoid> Endhlvoid(FlatBufferBuilder builder) {
    int o = builder.EndTable();
    return new Offset<Hyperlight.Generated.hlvoid>(o);
  }
  public hlvoidT UnPack() {
    var _o = new hlvoidT();
    this.UnPackTo(_o);
    return _o;
  }
  public void UnPackTo(hlvoidT _o) {
  }
  public static Offset<Hyperlight.Generated.hlvoid> Pack(FlatBufferBuilder builder, hlvoidT _o) {
    if (_o == null) return default(Offset<Hyperlight.Generated.hlvoid>);
    Starthlvoid(builder);
    return Endhlvoid(builder);
  }
}

public class hlvoidT
{

  public hlvoidT() {
  }
}


static public class hlvoidVerify
{
  static public bool Verify(Google.FlatBuffers.Verifier verifier, uint tablePos)
  {
    return verifier.VerifyTableStart(tablePos)
      && verifier.VerifyTableEnd(tablePos);
  }
}

}