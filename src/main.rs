use secp256k1::{SECP256K1, SecretKey, Parity, PublicKey, XOnlyPublicKey};
use rand_core::OsRng;

fn get_shared_point(private_key_a: SecretKey, x_only_public_key_b: XOnlyPublicKey) -> [u8; 32] {
    let pubkey = PublicKey::from_x_only_public_key(x_only_public_key_b, Parity::Even);
    let mut ssp = secp256k1::ecdh::shared_secret_point(&pubkey, &private_key_a)
        .as_slice()
        .to_owned();
    ssp.resize(32, 0); // toss the Y part
    ssp.try_into().unwrap()
}


fn main() {
    let mut secret_key_even;
    loop {
        secret_key_even = SecretKey::new(&mut OsRng);
        let (_, parity) = secret_key_even.x_only_public_key(&SECP256K1);
        if parity == Parity::Even {
            break;
        }
    }

    let mut secret_key_odd;
    loop {
        secret_key_odd = SecretKey::new(&mut OsRng);
        let (_, parity) = secret_key_odd.x_only_public_key(&SECP256K1);
        if parity == Parity::Odd {
            break;
        }
    }

    let point1 = get_shared_point(secret_key_even, secret_key_odd.x_only_public_key(&SECP256K1).0);
    let point2 = get_shared_point(secret_key_odd, secret_key_even.x_only_public_key(&SECP256K1).0);

    assert_eq!(point1, point2);

    println!("They are equal.");
}
