# Emits the Yul body of keccak-f[1600] (memory state: 25 words at `a`, scratch at `s`) for KaspaPow.sol.
R = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]  # R[x][y]
RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,
      0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,
      0x0000000080008009,0x000000008000000A,0x000000008000808B,0x800000000000008B,0x8000000000008089,
      0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
      0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
L = lambda i: f"mload(add(a, {32*i}))" if i else "mload(a)"
out = []
w = out.append
w("            function keccakF(a, s) {")
w("                // s: 25 words for B, 5 for C, 5 for D, 24 round constants. Lanes are 64-bit values in full words.")
w("                let m := 0xffffffffffffffff")
for i, rc in enumerate(RC):
    w(f"                mstore(add(s, {1120+32*i}), {hex(rc)})")
w("                for { let r := 0 } lt(r, 24) { r := add(r, 1) } {")
if True:
    for x in range(5):
        w(f"                {{ let c := xor(xor(xor(xor({L(x)}, {L(x+5)}), {L(x+10)}), {L(x+15)}), {L(x+20)}) mstore(add(s, {800+32*x}), c) }}")
    for x in range(5):
        c1 = f"mload(add(s, {800+32*((x+1)%5)}))"
        c4 = f"mload(add(s, {800+32*((x+4)%5)}))"
        # D[x] = C[x-1] ^ rotl(C[x+1],1); stored after all C are read -> use slots 960+
        w(f"                {{ let c := {c1} mstore(add(s, {960+32*x}), xor({c4}, and(or(shl(1, c), shr(63, c)), m))) }}")
    for x in range(5):
        for y in range(5):
            i = x + 5*y
            dest = y + 5*((2*x + 3*y) % 5)
            rot = R[x][y]
            v = f"xor({L(i)}, mload(add(s, {960+32*x})))"
            if rot == 0:
                w(f"                mstore(add(s, {32*dest}), {v})")
            else:
                w(f"                {{ let v := {v} mstore(add(s, {32*dest}), and(or(shl({rot}, v), shr({64-rot}, v)), m)) }}")
    for y in range(5):
        for x in range(5):
            b0 = f"mload(add(s, {32*(x+5*y)}))"
            b1 = f"mload(add(s, {32*((x+1)%5+5*y)}))"
            b2 = f"mload(add(s, {32*((x+2)%5+5*y)}))"
            val = f"xor({b0}, and(xor({b1}, m), {b2}))"
            if x == 0 and y == 0:
                val = f"xor({val}, mload(add(s, add(1120, shl(5, r)))))"
            w(f"                mstore(add(a, {32*(x+5*y)}), {val})")
w("                }")
w("            }")
open("/home/claude/kpow/gen/keccak.yul.inc", "w").write("\n".join(out) + "\n")
print(len(out), "lines")
