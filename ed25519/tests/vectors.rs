use ark_ff::MontFp;
use ed25519::{Fp, Keys};
use io_utils::hex;

pub const VECTORS_25519: &[(Keys, &[u8], [u8; 64])] = &[
    (
        Keys {
            private: hex!(
                "9d61b19deffd5a60ba844af492ec2cc4\
                 4449c5697b326919703bac031cae7f60"
            ),
            public: hex!(
                "d75a980182b10ab7d54bfed3c964073a\
                 0ee172f3daa62325af021a68f707511a"
            ),
        },
        &hex!(""),
        hex!(
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b"
        ),
    ),
    (
        Keys {
            private: hex!(
                "4ccd089b28ff96da9db6c346ec114e0f\
                 5b8a319f35aba624da8cf6ed4fb8a6fb"
            ),
            public: hex!(
                "3d4017c3e843895a92b70aa74d1b7ebc\
                 9c982ccf2ec4968cc0cd55f12af4660c"
            ),
        },
        &hex!("72"),
        hex!(
            "92a009a9f0d4cab8720e820b5f642540\
             a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c\
             387b2eaeb4302aeeb00d291612bb0c00"
        ),
    ),
    (
        Keys {
            private: hex!(
                "c5aa8df43f9f837bedb7442f31dcb7b1\
                 66d38535076f094b85ce3a2e0b4458f7"
            ),
            public: hex!(
                "fc51cd8e6218a1a38da47ed00230f058\
                 0816ed13ba3303ac5deb911548908025"
            ),
        },
        &hex!("af82"),
        hex!(
            "6291d657deec24024827e69c3abe01a3\
             0ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc659\
             4a7c15e9716ed28dc027beceea1ec40a"
        ),
    ),
    (
        Keys {
            private: hex!(
                "f5e5767cf153319517630f226876b86c\
                 8160cc583bc013744c6bf255f5cc0ee5"
            ),
            public: hex!(
                "278117fc144c72340f67d0f2316e8386\
                 ceffbf2b2428c9c51fef7c597f1d426e"
            ),
        },
        &hex!(
            "08b8b2b733424243760fe426a4b54908\
             632110a66c2f6591eabd3345e3e4eb98\
             fa6e264bf09efe12ee50f8f54e9f77b1\
             e355f6c50544e23fb1433ddf73be84d8\
             79de7c0046dc4996d9e773f4bc9efe57\
             38829adb26c81b37c93a1b270b20329d\
             658675fc6ea534e0810a4432826bf58c\
             941efb65d57a338bbd2e26640f89ffbc\
             1a858efcb8550ee3a5e1998bd177e93a\
             7363c344fe6b199ee5d02e82d522c4fe\
             ba15452f80288a821a579116ec6dad2b\
             3b310da903401aa62100ab5d1a36553e\
             06203b33890cc9b832f79ef80560ccb9\
             a39ce767967ed628c6ad573cb116dbef\
             efd75499da96bd68a8a97b928a8bbc10\
             3b6621fcde2beca1231d206be6cd9ec7\
             aff6f6c94fcd7204ed3455c68c83f4a4\
             1da4af2b74ef5c53f1d8ac70bdcb7ed1\
             85ce81bd84359d44254d95629e9855a9\
             4a7c1958d1f8ada5d0532ed8a5aa3fb2\
             d17ba70eb6248e594e1a2297acbbb39d\
             502f1a8c6eb6f1ce22b3de1a1f40cc24\
             554119a831a9aad6079cad88425de6bd\
             e1a9187ebb6092cf67bf2b13fd65f270\
             88d78b7e883c8759d2c4f5c65adb7553\
             878ad575f9fad878e80a0c9ba63bcbcc\
             2732e69485bbc9c90bfbd62481d9089b\
             eccf80cfe2df16a2cf65bd92dd597b07\
             07e0917af48bbb75fed413d238f5555a\
             7a569d80c3414a8d0859dc65a46128ba\
             b27af87a71314f318c782b23ebfe808b\
             82b0ce26401d2e22f04d83d1255dc51a\
             ddd3b75a2b1ae0784504df543af8969b\
             e3ea7082ff7fc9888c144da2af58429e\
             c96031dbcad3dad9af0dcbaaaf268cb8\
             fcffead94f3c7ca495e056a9b47acdb7\
             51fb73e666c6c655ade8297297d07ad1\
             ba5e43f1bca32301651339e22904cc8c\
             42f58c30c04aafdb038dda0847dd988d\
             cda6f3bfd15c4b4c4525004aa06eeff8\
             ca61783aacec57fb3d1f92b0fe2fd1a8\
             5f6724517b65e614ad6808d6f6ee34df\
             f7310fdc82aebfd904b01e1dc54b2927\
             094b2db68d6f903b68401adebf5a7e08\
             d78ff4ef5d63653a65040cf9bfd4aca7\
             984a74d37145986780fc0b16ac451649\
             de6188a7dbdf191f64b5fc5e2ab47b57\
             f7f7276cd419c17a3ca8e1b939ae49e4\
             88acba6b965610b5480109c8b17b80e1\
             b7b750dfc7598d5d5011fd2dcc5600a3\
             2ef5b52a1ecc820e308aa342721aac09\
             43bf6686b64b2579376504ccc493d97e\
             6aed3fb0f9cd71a43dd497f01f17c0e2\
             cb3797aa2a2f256656168e6c496afc5f\
             b93246f6b1116398a346f1a641f3b041\
             e989f7914f90cc2c7fff357876e506b5\
             0d334ba77c225bc307ba537152f3f161\
             0e4eafe595f6d9d90d11faa933a15ef1\
             369546868a7f3a45a96768d40fd9d034\
             12c091c6315cf4fde7cb68606937380d\
             b2eaaa707b4c4185c32eddcdd306705e\
             4dc1ffc872eeee475a64dfac86aba41c\
             0618983f8741c5ef68d3a101e8a3b8ca\
             c60c905c15fc910840b94c00a0b9d0"
        ),
        hex!(
            "0aab4c900501b3e24d7cdf4663326a3a\
             87df5e4843b2cbdb67cbf6e460fec350\
             aa5371b1508f9f4528ecea23c436d94b\
             5e8fcd4f681e30a6ac00a9704a188a03"
        ),
    ),
    (
        Keys {
            private: hex!(
                "833fe62409237b9d62ec77587520911e\
                 9a759cec1d19755b7da901b96dca3d42"
            ),
            public: hex!(
                "ec172b93ad5e563bf4932c70e1245034\
                 c35467ef2efd4d64ebf819683467e2bf"
            ),
        },
        &hex!(
            "ddaf35a193617abacc417349ae204131\
             12e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f"
        ),
        hex!(
            "dc2a4459e7369633a52b1bf277839a00\
             201009a3efbf3ecb69bea2186c26b589\
             09351fc9ac90b3ecfdfbc7c66431e030\
             3dca179c138ac17ad9bef1177331a704"
        ),
    ),
];

pub const ENCODING_25519: &[((Fp, Fp), [u8; 32])] = &[
    (
        (
            MontFp!(
                "38815646466658113194383306759739515082307681141926459231621296960732224964046"
            ),
            MontFp!(
                "11903303657706407974989296177215005343713679411332034699907763981919547054807"
            ),
        ),
        [
            0xd7, 0x5a, 0x98, 0x1, 0x82, 0xb1, 0xa, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x7,
            0x3a, 0xe, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x2, 0x1a, 0x68, 0xf7, 0x7,
            0x51, 0x1a,
        ],
    ),
    (
        (
            MontFp!(
                "52774231920053734232574595727734981596546427020284349182563870143297718469550"
            ),
            MontFp!("5609657767448528674903586191599477543993232845525898641911799861560072421437"),
        ),
        [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0xa, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0xc,
        ],
    ),
    (
        (
            MontFp!(
                "43933056957747458452560886832567536073542840507013052263144963060608791330050"
            ),
            MontFp!(
                "16962727616734173323702303146057009569815335830970791807500022961899349823996"
            ),
        ),
        [
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x2, 0x30,
            0xf0, 0x58, 0x8, 0x16, 0xed, 0x13, 0xba, 0x33, 0x3, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48,
            0x90, 0x80, 0x25,
        ],
    ),
    (
        (
            MontFp!(
                "18657470665189904117898550913318951530457522032339991377040573310803285005520"
            ),
            MontFp!(
                "49871228834416148598710216424367009781408512742280543963772643809550350647591"
            ),
        ),
        [
            0x27, 0x81, 0x17, 0xfc, 0x14, 0x4c, 0x72, 0x34, 0xf, 0x67, 0xd0, 0xf2, 0x31, 0x6e,
            0x83, 0x86, 0xce, 0xff, 0xbf, 0x2b, 0x24, 0x28, 0xc9, 0xc5, 0x1f, 0xef, 0x7c, 0x59,
            0x7f, 0x1d, 0x42, 0x6e,
        ],
    ),
    (
        (
            MontFp!(
                "40121575059854498688793601084330139334125048157368472832084429102603245386799"
            ),
            MontFp!(
                "28895729190139806181135174156803260194472099954421499683004293713963394996204"
            ),
        ),
        [
            0xec, 0x17, 0x2b, 0x93, 0xad, 0x5e, 0x56, 0x3b, 0xf4, 0x93, 0x2c, 0x70, 0xe1, 0x24,
            0x50, 0x34, 0xc3, 0x54, 0x67, 0xef, 0x2e, 0xfd, 0x4d, 0x64, 0xeb, 0xf8, 0x19, 0x68,
            0x34, 0x67, 0xe2, 0xbf,
        ],
    ),
];
