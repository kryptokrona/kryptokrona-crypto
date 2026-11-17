//! The multisig vectors of kryptokrona-crypto's `tests/crypto.ts` (computed with the 1.x
//! addon), on the Rust implementation.

use kryptokrona_crypto_extra::multisig::{
    calculate_multisig_private_keys, calculate_shared_private_key, calculate_shared_public_key,
    generate_partial_signing_key, restore_key_image, restore_ring_signatures,
};
use xkr_crypto_ffi::api;

struct Party {
    spend_secret: &'static str,
    spend_public: &'static str,
    view_secret: &'static str,
    multisig_secrets: [&'static str; 2],
    multisig_publics: [&'static str; 2],
}

const PARTY1: Party = Party {
    spend_secret: "a0ba0cae34ce1133b9cb658e5d0a56440608622a64562ac360907a2c68ea130d",
    spend_public: "6bce43e0d797b9ee674db41c173f9b147fab6841fed36e97d434bd7c6f5b81d5",
    view_secret: "01d85bf9ce5583c7a1039f2c2695cb562bf1ea97636bbaf9051af01dddc89e0b",
    multisig_secrets: [
        "ca67bdeba4cc489c86b0e6be24ed86ee75fd7e4caaf6566ea3b241946f40f901",
        "98c2625a77504c46fb4d83bdf2c5dee505d4e3d0d30005bac636b0d49f90420f",
    ],
    multisig_publics: [
        "c578447b97b8cd9a5234ec25ba2ba54f37ec5504ae40167414e700ebf2bfe2bb",
        "fe9ae30ba09e27f0dd50762321bd427b97ca43ab44e9c148e7508f2e4a3917b9",
    ],
};

const PARTY2: Party = Party {
    spend_secret: "91ace6308728a8e1c7d833b2fe9beb4a5a808ec04218e7da8402260a3872120d",
    spend_public: "ba719ff6486ae5ab5ea0c7e05f6b42468f898bd366f83a4d165e396c1f7c5eec",
    view_secret: "650110a79f0353624f0fa14aaaf8c5af405ddb009c3127366e5b8591ecec9704",
    multisig_secrets: [
        "1726bee3bd42cc2288a36524142d0369520673052d264309e2312e9c21d16a09",
        "ca67bdeba4cc489c86b0e6be24ed86ee75fd7e4caaf6566ea3b241946f40f901",
    ],
    multisig_publics: [
        "13a5ab919024895573616fa7e4b852b52444caa9c91df4a1dbb9493e148d5d03",
        "c578447b97b8cd9a5234ec25ba2ba54f37ec5504ae40167414e700ebf2bfe2bb",
    ],
};

const PARTY3: Party = Party {
    spend_secret: "42b79cc7ac0b05ef34cd08716efec28a73366b702fcc6a09c37f5428ee52a802",
    spend_public: "fd524a5384bf5044feeb61f19866e11f74b8dbf5e7d050238046b04289a31849",
    view_secret: "4f94fe294c541a5fe9740fa96ae86d70df9f51b13fe88ae5188ae59aae71910b",
    multisig_secrets: [
        "98c2625a77504c46fb4d83bdf2c5dee505d4e3d0d30005bac636b0d49f90420f",
        "1726bee3bd42cc2288a36524142d0369520673052d264309e2312e9c21d16a09",
    ],
    multisig_publics: [
        "fe9ae30ba09e27f0dd50762321bd427b97ca43ab44e9c148e7508f2e4a3917b9",
        "13a5ab919024895573616fa7e4b852b52444caa9c91df4a1dbb9493e148d5d03",
    ],
};

const PREFIX: &str = "b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0";
const DECOYS: [&str; 3] = [
    "492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862",
    "7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402",
    "bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460",
];

#[test]
fn two_of_two() {
    assert_eq!(
        calculate_shared_public_key(&[PARTY1.spend_public, PARTY2.spend_public]).unwrap(),
        "caa8f9aaf673ff2c055025942eeefde720a71281420ec8c42f0a817225db032b"
    );
    assert_eq!(
        calculate_shared_public_key(&[PARTY2.spend_public, PARTY1.spend_public]).unwrap(),
        "caa8f9aaf673ff2c055025942eeefde720a71281420ec8c42f0a817225db032b"
    );
    assert_eq!(
        calculate_shared_private_key(&[PARTY1.view_secret, PARTY2.view_secret]).unwrap(),
        "7905764354f6c3d11a7648d4f193b2f16b4ec698ff9ce12f747575afc9b53600"
    );

    let public_ephemeral = "e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0";
    let derivation = "9475ebaa9f869b06d967aa0ca09d1632f4b8a383211c8a66e39021bc04d80fc4";
    let key_image = "6865866ed8a25824e042e21dd36e946836b58b03366e489aecf979f444f599b0";
    let partials = [
        api::generate_key_image(public_ephemeral, PARTY1.spend_secret).unwrap(),
        api::generate_key_image(public_ephemeral, PARTY2.spend_secret).unwrap(),
    ];
    assert_eq!(
        restore_key_image(public_ephemeral, derivation, 2, &partials).unwrap(),
        key_image
    );

    let mut ring: Vec<&str> = DECOYS.to_vec();
    ring.push(public_ephemeral);
    let prepared = api::prepare_ring_signatures(PREFIX, key_image, &ring, 3, None).unwrap();
    let signing_keys = [
        generate_partial_signing_key(&prepared.signatures[3], PARTY1.spend_secret).unwrap(),
        generate_partial_signing_key(&prepared.signatures[3], PARTY2.spend_secret).unwrap(),
    ];
    let sigs = restore_ring_signatures(
        derivation,
        2,
        &signing_keys,
        3,
        &prepared.k,
        &prepared.signatures,
    )
    .unwrap();
    assert!(api::check_ring_signature(PREFIX, key_image, &ring, &sigs));
}

#[test]
fn two_of_three() {
    let shared_public = "2f5a5c955f8510bb8c6601a3c16149c9451ffcd7e906fafa5e70407d59a61e77";
    let shared_view = "c899746da04ade3004eb577d5c7c20624bee174a3f856c158dff5a4a7827c80b";
    for (me, others) in [
        (&PARTY1, [&PARTY2, &PARTY3]),
        (&PARTY2, [&PARTY3, &PARTY1]),
        (&PARTY3, [&PARTY1, &PARTY2]),
    ] {
        let publics = [others[0].spend_public, others[1].spend_public];
        assert_eq!(
            calculate_multisig_private_keys(me.spend_secret, &publics).unwrap(),
            me.multisig_secrets
        );
        let mut all: Vec<&str> = me.multisig_publics.to_vec();
        all.extend(others[0].multisig_publics);
        all.extend(others[1].multisig_publics);
        assert_eq!(calculate_shared_public_key(&all).unwrap(), shared_public);
        assert_eq!(
            calculate_shared_private_key(&[
                me.view_secret,
                others[0].view_secret,
                others[1].view_secret
            ])
            .unwrap(),
            shared_view
        );
    }

    let public_ephemeral = "71e91d548fc24e21ece8388550c209c0862ffd47320317ddd456aea757f8309b";
    let derivation = "f6c1094900adf5d36393fa52b1f086886fb939078a9b6c411a4207780fb89bf6";
    let key_image = "174d0e7323ec00fa3e0d8432ffd3614cac829685d32a0a5b8f107cef80043178";
    let partial_images = |parties: &[&Party]| -> Vec<String> {
        parties
            .iter()
            .flat_map(|p| p.multisig_secrets)
            .map(|secret| api::generate_key_image(public_ephemeral, secret).unwrap())
            .collect()
    };
    for parties in [
        vec![&PARTY1, &PARTY2],
        vec![&PARTY1, &PARTY3],
        vec![&PARTY2, &PARTY3],
        vec![&PARTY1, &PARTY2, &PARTY3],
    ] {
        assert_eq!(
            restore_key_image(public_ephemeral, derivation, 1, &partial_images(&parties)).unwrap(),
            key_image
        );
    }
    assert_ne!(
        restore_key_image(public_ephemeral, derivation, 1, &partial_images(&[&PARTY1])).unwrap(),
        key_image
    );

    let mut ring: Vec<&str> = DECOYS.to_vec();
    ring.push(public_ephemeral);
    for parties in [vec![&PARTY1, &PARTY2], vec![&PARTY2, &PARTY3]] {
        let prepared = api::prepare_ring_signatures(PREFIX, key_image, &ring, 3, None).unwrap();
        let signing_keys: Vec<String> = parties
            .iter()
            .flat_map(|p| p.multisig_secrets)
            .map(|secret| generate_partial_signing_key(&prepared.signatures[3], secret).unwrap())
            .collect();
        let sigs = restore_ring_signatures(
            derivation,
            1,
            &signing_keys,
            3,
            &prepared.k,
            &prepared.signatures,
        )
        .unwrap();
        assert!(api::check_ring_signature(PREFIX, key_image, &ring, &sigs));
    }
}
