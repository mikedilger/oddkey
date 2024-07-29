use secp256k1::{SECP256K1, SecretKey, Parity};
use nostr_types::{PrivateKey, PreEvent, Unixtime, EventKind, KeySigner, Signer};
use rand_core::OsRng;

fn main() {
    let keysigner_even = {
        let mut secret_key_even;
        loop {
            secret_key_even = SecretKey::new(&mut OsRng);
            let (_, parity) = secret_key_even.x_only_public_key(&SECP256K1);
            if parity == Parity::Even {
                break;
            }
        }

        let secret_key_even_hex = hex::encode(secret_key_even.as_ref());
        let private_key_even = PrivateKey::try_from_hex_string(&secret_key_even_hex).unwrap();
        let keysigner_even = KeySigner::from_private_key(private_key_even, "dummy", 2).unwrap();

        let pre_event_even = PreEvent {
            pubkey: keysigner_even.public_key(),
            created_at: Unixtime::now(),
            kind: EventKind::TextNote,
            tags: vec![],
            content: "testing".to_owned(),
        };
        let event_even = keysigner_even.sign_event(pre_event_even).unwrap();
        event_even.verify(None).unwrap();

        keysigner_even
    };

    let keysigner_odd = {
        let mut secret_key_odd;
        loop {
            secret_key_odd = SecretKey::new(&mut OsRng);
            let (_, parity) = secret_key_odd.x_only_public_key(&SECP256K1);
            if parity == Parity::Odd {
                break;
            }
        }

        let secret_key_odd_hex = hex::encode(secret_key_odd.as_ref());
        let private_key_odd = PrivateKey::try_from_hex_string(&secret_key_odd_hex).unwrap();
        let keysigner_odd = KeySigner::from_private_key(private_key_odd, "dummy", 2).unwrap();


        let pre_event_odd = PreEvent {
            pubkey: keysigner_odd.public_key(),
            created_at: Unixtime::now(),
            kind: EventKind::TextNote,
            tags: vec![],
            content: "testing".to_owned(),
        };
        let event_odd = keysigner_odd.sign_event(pre_event_odd).unwrap();
        event_odd.verify(None).unwrap();

        keysigner_odd
    };

    let even_convo = keysigner_even.nip44_conversation_key(&keysigner_odd.public_key()).unwrap();
    let odd_convo = keysigner_odd.nip44_conversation_key(&keysigner_even.public_key()).unwrap();

    assert_eq!(even_convo, odd_convo);

    println!("Done, they are interoperable.");
}
