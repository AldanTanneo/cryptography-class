use shake128::*;

const DATA: [u8; 200] = [
    0xe7, 0xdd, 0xe1, 0x40, 0x79, 0x8f, 0x25, 0xf1, 0x8a, 0x47, 0xc0, 0x33, 0xf9, 0xcc, 0xd5, 0x84,
    0xee, 0xa9, 0x5a, 0xa6, 0x1e, 0x26, 0x98, 0xd5, 0x4d, 0x49, 0x80, 0x6f, 0x30, 0x47, 0x15, 0xbd,
    0x57, 0xd0, 0x53, 0x62, 0x05, 0x4e, 0x28, 0x8b, 0xd4, 0x6f, 0x8e, 0x7f, 0x2d, 0xa4, 0x97, 0xff,
    0xc4, 0x47, 0x46, 0xa4, 0xa0, 0xe5, 0xfe, 0x90, 0x76, 0x2e, 0x19, 0xd6, 0x0c, 0xda, 0x5b, 0x8c,
    0x9c, 0x05, 0x19, 0x1b, 0xf7, 0xa6, 0x30, 0xad, 0x64, 0xfc, 0x8f, 0xd0, 0xb7, 0x5a, 0x93, 0x30,
    0x35, 0xd6, 0x17, 0x23, 0x3f, 0xa9, 0x5a, 0xeb, 0x03, 0x21, 0x71, 0x0d, 0x26, 0xe6, 0xa6, 0xa9,
    0x5f, 0x55, 0xcf, 0xdb, 0x16, 0x7c, 0xa5, 0x81, 0x26, 0xc8, 0x47, 0x03, 0xcd, 0x31, 0xb8, 0x43,
    0x9f, 0x56, 0xa5, 0x11, 0x1a, 0x2f, 0xf2, 0x01, 0x61, 0xae, 0xd9, 0x21, 0x5a, 0x63, 0xe5, 0x05,
    0xf2, 0x70, 0xc9, 0x8c, 0xf2, 0xfe, 0xbe, 0x64, 0x11, 0x66, 0xc4, 0x7b, 0x95, 0x70, 0x36, 0x61,
    0xcb, 0x0e, 0xd0, 0x4f, 0x55, 0x5a, 0x7c, 0xb8, 0xc8, 0x32, 0xcf, 0x1c, 0x8a, 0xe8, 0x3e, 0x8c,
    0x14, 0x26, 0x3a, 0xae, 0x22, 0x79, 0x0c, 0x94, 0xe4, 0x09, 0xc5, 0xa2, 0x24, 0xf9, 0x41, 0x18,
    0xc2, 0x65, 0x04, 0xe7, 0x26, 0x35, 0xf5, 0x16, 0x3b, 0xa1, 0x30, 0x7f, 0xe9, 0x44, 0xf6, 0x75,
    0x49, 0xa2, 0xec, 0x5c, 0x7b, 0xff, 0xf1, 0xea,
];

#[test]
fn parse_bit_string() {
    let parsed = State::from([
        [
            0xf1258f7940e1dde7,
            0x84d5ccf933c0478a,
            0xd598261ea65aa9ee,
            0xbd1547306f80494d,
            0x8b284e056253d057,
        ],
        [
            0xff97a42d7f8e6fd4,
            0x90fee5a0a44647c4,
            0x8c5bda0cd6192e76,
            0xad30a6f71b19059c,
            0x30935ab7d08ffc64,
        ],
        [
            0xeb5aa93f2317d635,
            0xa9a6e6260d712103,
            0x81a57c16dbcf555f,
            0x43b831cd0347c826,
            0x01f22f1a11a5569f,
        ],
        [
            0x05e5635a21d9ae61,
            0x64befef28cc970f2,
            0x613670957bc46611,
            0xb87c5a554fd00ecb,
            0x8c3ee88a1ccf32c8,
        ],
        [
            0x940c7922ae3a2614,
            0x1841f924a2c509e4,
            0x16f53526e70465c2,
            0x75f644e97f30a13b,
            0xeaf1ff7b5ceca249,
        ],
    ]);

    assert_eq!(State::from(DATA), parsed);
}

#[test]
fn after_theta() {
    let after = State::from([
        [
            0xaf463273ca4d877d,
            0xaf9fdf84cec209d0,
            0x28c573db9cdda7ba,
            0xabbcda349e794c02,
            0xfd3cb094025a23b6,
        ],
        [
            0xa1f41927f522354e,
            0xbbb4f6dd5944099e,
            0x71068fc9ec9e2022,
            0xbb993bf3eae000d3,
            0x4687a426b0860f85,
        ],
        [
            0xb5391435a9bb8caf,
            0x82ecf55bf0736f59,
            0x7cf829d3e1485b0b,
            0x5511acc9f2becd69,
            0x77e6d18b71aca57e,
        ],
        [
            0x5b86de50ab75f4fb,
            0x4ff4ed8f71cb3ea8,
            0x9c6b255041436845,
            0xaed5c751be290b84,
            0xfa2a161b7cc6c129,
        ],
        [
            0xca6fc42824967c8e,
            0x330bea595fc747be,
            0xeba860e3dd836b96,
            0x635fd9ed8ec9a474,
            0x9ce501ea3ce551a8,
        ],
    ]);

    let mut state = State::from(DATA);
    theta(&mut state);

    assert_eq!(state, after);
}

#[test]
fn after_rho() {
    let after = State::from([
        [
            0xaf463273ca4d877d,
            0x5f3fbf099d8413a1,
            0x8a315cf6e73769ee,
            0x49e794c02abbcda3,
            0xa012d11db7e9e584,
        ],
        [
            0x522354ea1f41927f,
            0x4099ebbb4f6dd594,
            0x41a3f27b2788089c,
            0x69ddcc9df9f57000,
            0x426b0860f854687a,
        ],
        [
            0xa9c8a1ad4ddc657d,
            0xb3d56fc1cdbd660b,
            0x42d85be7c14e9f0a,
            0x93e57d9ad2aa2359,
            0xd652bf3bf368c5b8,
        ],
        [
            0xebe9f6b70dbca156,
            0x67d509fe9db1ee39,
            0x92a820a1b422ce35,
            0xea37c5217095dab8,
            0x2a161b7cc6c129fa,
        ],
        [
            0x10a09259f23b29bf,
            0xcc2fa9657f1d1ef8,
            0xdd750c1c7bb06d72,
            0x74635fd9ed8ec9a4,
            0x407a8f39546a2739,
        ],
    ]);

    let mut state = State::from(DATA);
    rho(theta(&mut state));

    assert_eq!(state, after);
}

#[test]
fn after_pi() {
    let after = State::from([
        [
            0xaf463273ca4d877d,
            0x4099ebbb4f6dd594,
            0x42d85be7c14e9f0a,
            0xea37c5217095dab8,
            0x407a8f39546a2739,
        ],
        [
            0x49e794c02abbcda3,
            0x426b0860f854687a,
            0xa9c8a1ad4ddc657d,
            0x67d509fe9db1ee39,
            0xdd750c1c7bb06d72,
        ],
        [
            0x5f3fbf099d8413a1,
            0x41a3f27b2788089c,
            0x93e57d9ad2aa2359,
            0x2a161b7cc6c129fa,
            0x10a09259f23b29bf,
        ],
        [
            0xa012d11db7e9e584,
            0x522354ea1f41927f,
            0xb3d56fc1cdbd660b,
            0x92a820a1b422ce35,
            0x74635fd9ed8ec9a4,
        ],
        [
            0x8a315cf6e73769ee,
            0x69ddcc9df9f57000,
            0xd652bf3bf368c5b8,
            0xebe9f6b70dbca156,
            0xcc2fa9657f1d1ef8,
        ],
    ]);

    let mut state = State::from(DATA);
    pi(rho(theta(&mut state)));

    assert_eq!(state, after);
}

#[test]
fn after_chi() {
    let after = State::from([
        [
            0xad0622374a4f8d77,
            0xe8be6fbb7ffc9524,
            0x429051ffc524ba0b,
            0x4533f563fa905afc,
            0x00e346b1514a77b9,
        ],
        [
            0xe067354d2f33c8a6,
            0x047e00326875e27a,
            0x31e8a5ad2fdc643f,
            0x6757993e9dba6eb8,
            0xdf7d043cabf44d2a,
        ],
        [
            0xcd7bb2894da630e0,
            0x69b1f01f23c9003e,
            0x8345fd9be290235c,
            0x6509367ccb453bfa,
            0x1020d22bd03321a3,
        ],
        [
            0x01c6fa1c77558184,
            0x520b54ca2f431a4b,
            0xd79630998431678b,
            0x12b8a0a5a643ea35,
            0x26425b3be58edbdf,
        ],
        [
            0x1c336fd4e53fec56,
            0x40748c19f5615046,
            0xd254b67b8169db10,
            0xe9f9a2258d9ec050,
            0xade3296c67dd0ef8,
        ],
    ]);

    let mut state = State::from(DATA);
    chi(pi(rho(theta(&mut state))));

    assert_eq!(state, after)
}

#[test]
fn round_constants() {
    let rc = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    assert_eq!(make_round_constants(), rc);
}

#[test]
fn after_round() {
    let after_one = State::from([
        [
            0xad0622374a4f8d76,
            0xe8be6fbb7ffc9524,
            0x429051ffc524ba0b,
            0x4533f563fa905afc,
            0x00e346b1514a77b9,
        ],
        [
            0xe067354d2f33c8a6,
            0x047e00326875e27a,
            0x31e8a5ad2fdc643f,
            0x6757993e9dba6eb8,
            0xdf7d043cabf44d2a,
        ],
        [
            0xcd7bb2894da630e0,
            0x69b1f01f23c9003e,
            0x8345fd9be290235c,
            0x6509367ccb453bfa,
            0x1020d22bd03321a3,
        ],
        [
            0x01c6fa1c77558184,
            0x520b54ca2f431a4b,
            0xd79630998431678b,
            0x12b8a0a5a643ea35,
            0x26425b3be58edbdf,
        ],
        [
            0x1c336fd4e53fec56,
            0x40748c19f5615046,
            0xd254b67b8169db10,
            0xe9f9a2258d9ec050,
            0xade3296c67dd0ef8,
        ],
    ]);
    let after_two = State::from([
        [
            0x672D4E0D264DB92C,
            0x1A84BFA087E4FB8B,
            0xB2EC97619AECE89C,
            0xCEBE13CAC549DE27,
            0x54FC146106194E84,
        ],
        [
            0x8B23BDEA5F2F1AFE,
            0x8E8C9267B1555861,
            0x3C46FF954DED256C,
            0xC86854F37CD6FBB0,
            0x03244A0A2C4D75B8,
        ],
        [
            0x7D7792A1F6691ECB,
            0x3FD486E0A64AF877,
            0x67B7914C6C118AB9,
            0x81276E3FC0DFC5A2,
            0x8C3A2CC762ED79F4,
        ],
        [
            0x3874CB197C10E7F9,
            0xD291F63B2EC58375,
            0x0BE9C36C033DEF63,
            0x5347708E98801482,
            0x0F173D486F940319,
        ],
        [
            0x2B633DFC491DD734,
            0x3CED4BFDF9681BDF,
            0x310AD7CBBDB65F99,
            0xBC0BB0F982245E36,
            0x491ECBD0E4A725C5,
        ],
    ]);

    let mut state = State::from(DATA);

    iota(chi(pi(rho(theta(&mut state)))), 0);
    assert_eq!(state, after_one);

    round(&mut state, 1);
    assert_eq!(state, after_two);
}

#[test]
fn after_keccak_p() {
    // ensure our 'data' array is correctly aligned
    // so that we can safely cast it to State
    #[repr(align(8))]
    struct AlignedData([u8; 200]);

    impl std::ops::Deref for AlignedData {
        type Target = [u8; 200];
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl std::ops::DerefMut for AlignedData {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    let after = [
        0xE7, 0xDD, 0xE1, 0x40, 0x79, 0x8F, 0x25, 0xF1, 0x8A, 0x47, 0xC0, 0x33, 0xF9, 0xCC, 0xD5,
        0x84, 0xEE, 0xA9, 0x5A, 0xA6, 0x1E, 0x26, 0x98, 0xD5, 0x4D, 0x49, 0x80, 0x6F, 0x30, 0x47,
        0x15, 0xBD, 0x57, 0xD0, 0x53, 0x62, 0x05, 0x4E, 0x28, 0x8B, 0xD4, 0x6F, 0x8E, 0x7F, 0x2D,
        0xA4, 0x97, 0xFF, 0xC4, 0x47, 0x46, 0xA4, 0xA0, 0xE5, 0xFE, 0x90, 0x76, 0x2E, 0x19, 0xD6,
        0x0C, 0xDA, 0x5B, 0x8C, 0x9C, 0x05, 0x19, 0x1B, 0xF7, 0xA6, 0x30, 0xAD, 0x64, 0xFC, 0x8F,
        0xD0, 0xB7, 0x5A, 0x93, 0x30, 0x35, 0xD6, 0x17, 0x23, 0x3F, 0xA9, 0x5A, 0xEB, 0x03, 0x21,
        0x71, 0x0D, 0x26, 0xE6, 0xA6, 0xA9, 0x5F, 0x55, 0xCF, 0xDB, 0x16, 0x7C, 0xA5, 0x81, 0x26,
        0xC8, 0x47, 0x03, 0xCD, 0x31, 0xB8, 0x43, 0x9F, 0x56, 0xA5, 0x11, 0x1A, 0x2F, 0xF2, 0x01,
        0x61, 0xAE, 0xD9, 0x21, 0x5A, 0x63, 0xE5, 0x05, 0xF2, 0x70, 0xC9, 0x8C, 0xF2, 0xFE, 0xBE,
        0x64, 0x11, 0x66, 0xC4, 0x7B, 0x95, 0x70, 0x36, 0x61, 0xCB, 0x0E, 0xD0, 0x4F, 0x55, 0x5A,
        0x7C, 0xB8, 0xC8, 0x32, 0xCF, 0x1C, 0x8A, 0xE8, 0x3E, 0x8C, 0x14, 0x26, 0x3A, 0xAE, 0x22,
        0x79, 0x0C, 0x94, 0xE4, 0x09, 0xC5, 0xA2, 0x24, 0xF9, 0x41, 0x18, 0xC2, 0x65, 0x04, 0xE7,
        0x26, 0x35, 0xF5, 0x16, 0x3B, 0xA1, 0x30, 0x7F, 0xE9, 0x44, 0xF6, 0x75, 0x49, 0xA2, 0xEC,
        0x5C, 0x7B, 0xFF, 0xF1, 0xEA,
    ];

    let mut data = AlignedData([0; 200]);
    keccak_p(&mut data);

    assert_eq!(&*data, &after);
}
