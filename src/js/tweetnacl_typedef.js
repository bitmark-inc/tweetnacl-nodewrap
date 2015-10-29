var ref = require('ref');

var sv = ref.types.void;
var u8 = ref.types.CString;
var u8Ptr = ref.refType(u8);
var u32 = ref.types.ulong;
var u32Ptr = ref.refType(u32);
var u64 = ref.types.ulonglong;
var u64Ptr = ref.refType(u64);
var i64 = ref.types.longlong;
var i64Ptr = ref.refType(i64);


module.exports = function() {
  var typedef = {
    // typedef
    "ref": ref,
    "sv": ref.types.void,
    "u8": ref.types.CString,
    "u8Ptr": ref.refType(u8),
    "u32": ref.types.ulong,
    "u32Ptr": ref.refType(u32),
    "u64": ref.types.ulonglong,
    "u64Ptr": ref.refType(u64),
    "i64": ref.types.longlong,
    "i64Ptr": ref.refType(i64)
  };
  return typedef;
};