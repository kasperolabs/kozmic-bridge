            function keccakF(a, s) {
                // s: 25 words for B, 5 for C, 5 for D, 24 round constants. Lanes are 64-bit values in full words.
                let m := 0xffffffffffffffff
                mstore(add(s, 1120), 0x1)
                mstore(add(s, 1152), 0x8082)
                mstore(add(s, 1184), 0x800000000000808a)
                mstore(add(s, 1216), 0x8000000080008000)
                mstore(add(s, 1248), 0x808b)
                mstore(add(s, 1280), 0x80000001)
                mstore(add(s, 1312), 0x8000000080008081)
                mstore(add(s, 1344), 0x8000000000008009)
                mstore(add(s, 1376), 0x8a)
                mstore(add(s, 1408), 0x88)
                mstore(add(s, 1440), 0x80008009)
                mstore(add(s, 1472), 0x8000000a)
                mstore(add(s, 1504), 0x8000808b)
                mstore(add(s, 1536), 0x800000000000008b)
                mstore(add(s, 1568), 0x8000000000008089)
                mstore(add(s, 1600), 0x8000000000008003)
                mstore(add(s, 1632), 0x8000000000008002)
                mstore(add(s, 1664), 0x8000000000000080)
                mstore(add(s, 1696), 0x800a)
                mstore(add(s, 1728), 0x800000008000000a)
                mstore(add(s, 1760), 0x8000000080008081)
                mstore(add(s, 1792), 0x8000000000008080)
                mstore(add(s, 1824), 0x80000001)
                mstore(add(s, 1856), 0x8000000080008008)
                for { let r := 0 } lt(r, 24) { r := add(r, 1) } {
                { let c := xor(xor(xor(xor(mload(a), mload(add(a, 160))), mload(add(a, 320))), mload(add(a, 480))), mload(add(a, 640))) mstore(add(s, 800), c) }
                { let c := xor(xor(xor(xor(mload(add(a, 32)), mload(add(a, 192))), mload(add(a, 352))), mload(add(a, 512))), mload(add(a, 672))) mstore(add(s, 832), c) }
                { let c := xor(xor(xor(xor(mload(add(a, 64)), mload(add(a, 224))), mload(add(a, 384))), mload(add(a, 544))), mload(add(a, 704))) mstore(add(s, 864), c) }
                { let c := xor(xor(xor(xor(mload(add(a, 96)), mload(add(a, 256))), mload(add(a, 416))), mload(add(a, 576))), mload(add(a, 736))) mstore(add(s, 896), c) }
                { let c := xor(xor(xor(xor(mload(add(a, 128)), mload(add(a, 288))), mload(add(a, 448))), mload(add(a, 608))), mload(add(a, 768))) mstore(add(s, 928), c) }
                { let c := mload(add(s, 832)) mstore(add(s, 960), xor(mload(add(s, 928)), and(or(shl(1, c), shr(63, c)), m))) }
                { let c := mload(add(s, 864)) mstore(add(s, 992), xor(mload(add(s, 800)), and(or(shl(1, c), shr(63, c)), m))) }
                { let c := mload(add(s, 896)) mstore(add(s, 1024), xor(mload(add(s, 832)), and(or(shl(1, c), shr(63, c)), m))) }
                { let c := mload(add(s, 928)) mstore(add(s, 1056), xor(mload(add(s, 864)), and(or(shl(1, c), shr(63, c)), m))) }
                { let c := mload(add(s, 800)) mstore(add(s, 1088), xor(mload(add(s, 896)), and(or(shl(1, c), shr(63, c)), m))) }
                mstore(add(s, 0), xor(mload(a), mload(add(s, 960))))
                { let v := xor(mload(add(a, 160)), mload(add(s, 960))) mstore(add(s, 512), and(or(shl(36, v), shr(28, v)), m)) }
                { let v := xor(mload(add(a, 320)), mload(add(s, 960))) mstore(add(s, 224), and(or(shl(3, v), shr(61, v)), m)) }
                { let v := xor(mload(add(a, 480)), mload(add(s, 960))) mstore(add(s, 736), and(or(shl(41, v), shr(23, v)), m)) }
                { let v := xor(mload(add(a, 640)), mload(add(s, 960))) mstore(add(s, 448), and(or(shl(18, v), shr(46, v)), m)) }
                { let v := xor(mload(add(a, 32)), mload(add(s, 992))) mstore(add(s, 320), and(or(shl(1, v), shr(63, v)), m)) }
                { let v := xor(mload(add(a, 192)), mload(add(s, 992))) mstore(add(s, 32), and(or(shl(44, v), shr(20, v)), m)) }
                { let v := xor(mload(add(a, 352)), mload(add(s, 992))) mstore(add(s, 544), and(or(shl(10, v), shr(54, v)), m)) }
                { let v := xor(mload(add(a, 512)), mload(add(s, 992))) mstore(add(s, 256), and(or(shl(45, v), shr(19, v)), m)) }
                { let v := xor(mload(add(a, 672)), mload(add(s, 992))) mstore(add(s, 768), and(or(shl(2, v), shr(62, v)), m)) }
                { let v := xor(mload(add(a, 64)), mload(add(s, 1024))) mstore(add(s, 640), and(or(shl(62, v), shr(2, v)), m)) }
                { let v := xor(mload(add(a, 224)), mload(add(s, 1024))) mstore(add(s, 352), and(or(shl(6, v), shr(58, v)), m)) }
                { let v := xor(mload(add(a, 384)), mload(add(s, 1024))) mstore(add(s, 64), and(or(shl(43, v), shr(21, v)), m)) }
                { let v := xor(mload(add(a, 544)), mload(add(s, 1024))) mstore(add(s, 576), and(or(shl(15, v), shr(49, v)), m)) }
                { let v := xor(mload(add(a, 704)), mload(add(s, 1024))) mstore(add(s, 288), and(or(shl(61, v), shr(3, v)), m)) }
                { let v := xor(mload(add(a, 96)), mload(add(s, 1056))) mstore(add(s, 160), and(or(shl(28, v), shr(36, v)), m)) }
                { let v := xor(mload(add(a, 256)), mload(add(s, 1056))) mstore(add(s, 672), and(or(shl(55, v), shr(9, v)), m)) }
                { let v := xor(mload(add(a, 416)), mload(add(s, 1056))) mstore(add(s, 384), and(or(shl(25, v), shr(39, v)), m)) }
                { let v := xor(mload(add(a, 576)), mload(add(s, 1056))) mstore(add(s, 96), and(or(shl(21, v), shr(43, v)), m)) }
                { let v := xor(mload(add(a, 736)), mload(add(s, 1056))) mstore(add(s, 608), and(or(shl(56, v), shr(8, v)), m)) }
                { let v := xor(mload(add(a, 128)), mload(add(s, 1088))) mstore(add(s, 480), and(or(shl(27, v), shr(37, v)), m)) }
                { let v := xor(mload(add(a, 288)), mload(add(s, 1088))) mstore(add(s, 192), and(or(shl(20, v), shr(44, v)), m)) }
                { let v := xor(mload(add(a, 448)), mload(add(s, 1088))) mstore(add(s, 704), and(or(shl(39, v), shr(25, v)), m)) }
                { let v := xor(mload(add(a, 608)), mload(add(s, 1088))) mstore(add(s, 416), and(or(shl(8, v), shr(56, v)), m)) }
                { let v := xor(mload(add(a, 768)), mload(add(s, 1088))) mstore(add(s, 128), and(or(shl(14, v), shr(50, v)), m)) }
                mstore(add(a, 0), xor(xor(mload(add(s, 0)), and(xor(mload(add(s, 32)), m), mload(add(s, 64)))), mload(add(s, add(1120, shl(5, r))))))
                mstore(add(a, 32), xor(mload(add(s, 32)), and(xor(mload(add(s, 64)), m), mload(add(s, 96)))))
                mstore(add(a, 64), xor(mload(add(s, 64)), and(xor(mload(add(s, 96)), m), mload(add(s, 128)))))
                mstore(add(a, 96), xor(mload(add(s, 96)), and(xor(mload(add(s, 128)), m), mload(add(s, 0)))))
                mstore(add(a, 128), xor(mload(add(s, 128)), and(xor(mload(add(s, 0)), m), mload(add(s, 32)))))
                mstore(add(a, 160), xor(mload(add(s, 160)), and(xor(mload(add(s, 192)), m), mload(add(s, 224)))))
                mstore(add(a, 192), xor(mload(add(s, 192)), and(xor(mload(add(s, 224)), m), mload(add(s, 256)))))
                mstore(add(a, 224), xor(mload(add(s, 224)), and(xor(mload(add(s, 256)), m), mload(add(s, 288)))))
                mstore(add(a, 256), xor(mload(add(s, 256)), and(xor(mload(add(s, 288)), m), mload(add(s, 160)))))
                mstore(add(a, 288), xor(mload(add(s, 288)), and(xor(mload(add(s, 160)), m), mload(add(s, 192)))))
                mstore(add(a, 320), xor(mload(add(s, 320)), and(xor(mload(add(s, 352)), m), mload(add(s, 384)))))
                mstore(add(a, 352), xor(mload(add(s, 352)), and(xor(mload(add(s, 384)), m), mload(add(s, 416)))))
                mstore(add(a, 384), xor(mload(add(s, 384)), and(xor(mload(add(s, 416)), m), mload(add(s, 448)))))
                mstore(add(a, 416), xor(mload(add(s, 416)), and(xor(mload(add(s, 448)), m), mload(add(s, 320)))))
                mstore(add(a, 448), xor(mload(add(s, 448)), and(xor(mload(add(s, 320)), m), mload(add(s, 352)))))
                mstore(add(a, 480), xor(mload(add(s, 480)), and(xor(mload(add(s, 512)), m), mload(add(s, 544)))))
                mstore(add(a, 512), xor(mload(add(s, 512)), and(xor(mload(add(s, 544)), m), mload(add(s, 576)))))
                mstore(add(a, 544), xor(mload(add(s, 544)), and(xor(mload(add(s, 576)), m), mload(add(s, 608)))))
                mstore(add(a, 576), xor(mload(add(s, 576)), and(xor(mload(add(s, 608)), m), mload(add(s, 480)))))
                mstore(add(a, 608), xor(mload(add(s, 608)), and(xor(mload(add(s, 480)), m), mload(add(s, 512)))))
                mstore(add(a, 640), xor(mload(add(s, 640)), and(xor(mload(add(s, 672)), m), mload(add(s, 704)))))
                mstore(add(a, 672), xor(mload(add(s, 672)), and(xor(mload(add(s, 704)), m), mload(add(s, 736)))))
                mstore(add(a, 704), xor(mload(add(s, 704)), and(xor(mload(add(s, 736)), m), mload(add(s, 768)))))
                mstore(add(a, 736), xor(mload(add(s, 736)), and(xor(mload(add(s, 768)), m), mload(add(s, 640)))))
                mstore(add(a, 768), xor(mload(add(s, 768)), and(xor(mload(add(s, 640)), m), mload(add(s, 672)))))
                }
            }
