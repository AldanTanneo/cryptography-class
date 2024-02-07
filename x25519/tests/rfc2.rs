use io_utils::parse_hex;
use x25519::{x25519, x448, Curve25519, Curve448};

// on my machine in release mode, takes ~2min to run
#[test]
#[ignore = "takes long to run"]
fn x25519_iter() {
    let mut u = *Curve25519::BASE_POINT_BYTES;
    let mut k = *Curve25519::BASE_POINT_BYTES;

    let it1 = parse_hex::<32>("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        .unwrap();
    let it1_000 =
        parse_hex::<32>("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
            .unwrap();
    let it1_000_000 =
        parse_hex::<32>("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424")
            .unwrap();

    for _ in 0..1 {
        let new_k = x25519(&k, &u);
        u = k;
        k = new_k;
    }

    assert_eq!(&it1, &k, "Failed at 1st iteration");

    for _ in 1..1_000 {
        let new_k = x25519(&k, &u);
        u = k;
        k = new_k;
    }

    assert_eq!(&it1_000, &k, "Failed at 1000th iteration");

    for _ in 1_000..1_000_000 {
        let new_k = x25519(&k, &u);
        u = k;
        k = new_k;
    }

    assert_eq!(&it1_000_000, &k, "Failed at 1000_000th iteration");
}

// on my machine in release mode, takes ~6min to run
#[test]
#[ignore = "takes long to run"]
fn x448_iter() {
    let mut u = *Curve448::BASE_POINT_BYTES;
    let mut k = *Curve448::BASE_POINT_BYTES;

    let it1 = parse_hex::<56>(
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a\
         4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
    )
    .unwrap();
    let it1_000 = parse_hex::<56>(
        "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4\
         af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38",
    )
    .unwrap();
    let it1_000_000 = parse_hex::<56>(
        "077f453681caca3693198420bbe515cae0002472519b3e67661a7e89\
         cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37",
    )
    .unwrap();

    for _ in 0..1 {
        let new_k = x448(&k, &u);
        u = k;
        k = new_k;
    }

    assert_eq!(&it1, &k, "Failed at 1st iteration");

    for _ in 1..1_000 {
        let new_k = x448(&k, &u);
        u = k;
        k = new_k;
    }

    assert_eq!(&it1_000, &k, "Failed at 1000th iteration");

    for _ in 1_000..1_000_000 {
        let new_k = x448(&k, &u);
        u = k;
        k = new_k;
    }

    assert_eq!(&it1_000_000, &k, "Failed at 1000_000th iteration");
}
