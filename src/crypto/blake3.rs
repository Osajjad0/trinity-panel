//! BLAKE3, portable reference implementation.
//!
//! # Why this is hand-written
//!
//! The `blake3` crate cannot be built on every toolchain this project targets:
//! its build script pulls in `cc`, and a Rust host that links with the bundled
//! `rust-lld` rather than an external linker cannot satisfy that build
//! script's own link step. Shadowsocks-2022 needs BLAKE3 for key derivation,
//! so it has to be pure Rust with no build script and no dependencies.
//!
//! # Why hand-writing it is defensible here
//!
//! Hand-rolled cryptography is normally a bad idea, and the reason it is
//! acceptable in this one case is that **correctness is externally checkable**.
//! BLAKE3 publishes official test vectors, and this module is checked against
//! 22 of the 35 for all three modes — `hash`, `keyed_hash` and `derive_key` —
//! at input lengths from 0 to 102,400 bytes. The 22 are the ones sitting on a
//! structural boundary: sub-block, exactly one block, either side of the
//! 1024-byte chunk boundary, the first multi-chunk tree, and inputs deep
//! enough for several levels of parent nodes. An implementation that passes
//! only short inputs is wrong in a way that stays silent right up until it
//! derives a key nothing else agrees with.
//!
//! This is the portable implementation. No SIMD, no `unsafe`. It runs on key
//! derivation — once per session — not on the packet path, so clarity beats
//! throughput.

const OUT_LEN: usize = 32;
const KEY_LEN: usize = 32;
// Declared as u32 first and widened, rather than declared as usize and
// narrowed at each use. Widening is lossless on every supported target;
// narrowing needs a cast the compiler cannot prove safe, at four call sites.
const BLOCK_LEN_U32: u32 = 64;
const BLOCK_LEN: usize = BLOCK_LEN_U32 as usize;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB,
    0x5BE0_CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// The maximum depth of the subtree stack.
///
/// One entry per bit of the chunk counter: a 2^64-chunk input needs 54 levels
/// given BLAKE3's chunk size. Sized once so the hasher never allocates.
const MAX_DEPTH: usize = 54;

#[inline]
#[allow(clippy::many_single_char_names)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Columns.
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let original = *m;
    for (i, &p) in MSG_PERMUTATION.iter().enumerate() {
        m[i] = original[p];
    }
}

fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    #[allow(clippy::cast_possible_truncation)]
    let counter_low = counter as u32;
    #[allow(clippy::cast_possible_truncation)]
    let counter_high = (counter >> 32) as u32;
    let mut state: [u32; 16] = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter_low,
        counter_high,
        block_len,
        flags,
    ];
    let mut block = *block_words;

    for r in 0..7 {
        round(&mut state, &block);
        if r < 6 {
            permute(&mut block);
        }
    }

    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
    let mut out = [0u32; 8];
    out.copy_from_slice(&compression_output[..8]);
    out
}

fn words_from_le_bytes(bytes: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for (word, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        // chunks_exact(4) always yields 4 bytes; the fallback keeps this
        // panic-free without an unwrap.
        let mut b = [0u8; 4];
        b.copy_from_slice(chunk);
        *word = u32::from_le_bytes(b);
    }
    out
}

/// A node whose output can be extended to any length.
#[derive(Clone, Copy)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    /// Extendable output. Shadowsocks only needs 32 bytes, but the XOF is what
    /// makes the root node's definition well-formed, and implementing it
    /// partially is how subtle bugs appear at exactly 64-byte boundaries.
    fn root_output_bytes(&self, out: &mut [u8]) {
        for (counter, chunk) in out.chunks_mut(2 * OUT_LEN).enumerate() {
            let words = compress(
                &self.input_chaining_value,
                &self.block_words,
                counter as u64,
                self.block_len,
                self.flags | ROOT,
            );
            for (out_word, word) in chunk.chunks_mut(4).zip(words.iter()) {
                let bytes = word.to_le_bytes();
                out_word.copy_from_slice(&bytes[..out_word.len()]);
            }
        }
    }
}

struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value: key_words,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * usize::from(self.blocks_compressed) + usize::from(self.block_len)
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if usize::from(self.block_len) == BLOCK_LEN {
                let block_words = words_from_le_bytes(&self.block);
                self.chaining_value = first_8_words(compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN_U32,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }

            let want = BLOCK_LEN - usize::from(self.block_len);
            let take = want.min(input.len());
            self.block[usize::from(self.block_len)..usize::from(self.block_len) + take]
                .copy_from_slice(&input[..take]);
            #[allow(clippy::cast_possible_truncation)]
            {
                self.block_len += take as u8;
            }
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_chaining_value: self.chaining_value,
            block_words: words_from_le_bytes(&self.block),
            counter: self.chunk_counter,
            block_len: u32::from(self.block_len),
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(
    left: [u32; 8],
    right: [u32; 8],
    key_words: [u32; 8],
    flags: u32,
) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left);
    block_words[8..].copy_from_slice(&right);
    Output {
        input_chaining_value: key_words,
        block_words,
        counter: 0, // parents always use counter 0
        block_len: BLOCK_LEN_U32,
        flags: PARENT | flags,
    }
}

/// Incremental BLAKE3 hasher.
pub struct Hasher {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    cv_stack: [[u32; 8]; MAX_DEPTH],
    cv_stack_len: u8,
    flags: u32,
}

impl Hasher {
    fn new_internal(key_words: [u32; 8], flags: u32) -> Self {
        Self {
            chunk_state: ChunkState::new(key_words, 0, flags),
            key_words,
            cv_stack: [[0; 8]; MAX_DEPTH],
            cv_stack_len: 0,
            flags,
        }
    }

    /// Unkeyed hashing.
    #[must_use]
    pub fn new() -> Self {
        Self::new_internal(IV, 0)
    }

    /// Keyed hashing with a 32-byte key.
    #[must_use]
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        let mut key_words = [0u32; 8];
        for (word, chunk) in key_words.iter_mut().zip(key.chunks_exact(4)) {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            *word = u32::from_le_bytes(b);
        }
        Self::new_internal(key_words, KEYED_HASH)
    }

    /// Key derivation. The context string should be hardcoded, globally
    /// unique, and application-specific — that is what separates keys derived
    /// for different purposes from the same material.
    #[must_use]
    pub fn new_derive_key(context: &str) -> Self {
        let mut context_hasher = Self::new_internal(IV, DERIVE_KEY_CONTEXT);
        context_hasher.update(context.as_bytes());
        let mut context_key = [0u8; KEY_LEN];
        context_hasher.finalize(&mut context_key);

        let mut context_key_words = [0u32; 8];
        for (word, chunk) in context_key_words.iter_mut().zip(context_key.chunks_exact(4)) {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            *word = u32::from_le_bytes(b);
        }
        Self::new_internal(context_key_words, DERIVE_KEY_MATERIAL)
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        if usize::from(self.cv_stack_len) < MAX_DEPTH {
            self.cv_stack[usize::from(self.cv_stack_len)] = cv;
            self.cv_stack_len += 1;
        }
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        if self.cv_stack_len == 0 {
            return [0; 8];
        }
        self.cv_stack_len -= 1;
        self.cv_stack[usize::from(self.cv_stack_len)]
    }

    /// Merge completed subtrees. The number of trailing zero bits in the
    /// chunk counter is exactly how many merges are due — that is the trick
    /// that lets the tree be built without buffering the whole input.
    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let left = self.pop_stack();
            new_cv = parent_output(left, new_cv, self.key_words, self.flags).chaining_value();
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(self.key_words, total_chunks, self.flags);
            }

            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    pub fn finalize(&self, out: &mut [u8]) {
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = usize::from(self.cv_stack_len);
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output = parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            );
        }
        output.root_output_bytes(out);
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot unkeyed hash.
#[must_use]
pub fn hash(input: &[u8]) -> [u8; OUT_LEN] {
    let mut h = Hasher::new();
    h.update(input);
    let mut out = [0u8; OUT_LEN];
    h.finalize(&mut out);
    out
}

/// One-shot keyed hash.
#[must_use]
pub fn keyed_hash(key: &[u8; KEY_LEN], input: &[u8]) -> [u8; OUT_LEN] {
    let mut h = Hasher::new_keyed(key);
    h.update(input);
    let mut out = [0u8; OUT_LEN];
    h.finalize(&mut out);
    out
}

/// Derive a 32-byte subkey from key material under a context string.
///
/// This is the mode Shadowsocks-2022 uses.
#[must_use]
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; OUT_LEN] {
    let mut h = Hasher::new_derive_key(context);
    h.update(key_material);
    let mut out = [0u8; OUT_LEN];
    h.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The official vectors' input pattern: a repeating 251-byte ramp.
    fn test_input(len: usize) -> Vec<u8> {
        #[allow(clippy::cast_possible_truncation)]
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    const TEST_KEY: &[u8; 32] = b"whats the Elvish word for friend";
    const TEST_CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// The official vectors, verbatim, truncated to the first 32 output bytes.
    ///
    /// `(input_len, hash, keyed_hash, derive_key)`. Generated from the
    /// upstream `test_vectors.json` rather than transcribed by hand — an
    /// earlier draft of this table was written from memory, which is precisely
    /// the mistake these tests exist to catch, and several values were wrong.
    ///
    /// The lengths cover every structural boundary that matters: sub-block,
    /// exactly one block, either side of the 1024-byte chunk boundary, the
    /// first multi-chunk tree, and inputs deep enough to exercise several
    /// levels of parent nodes.
    #[allow(clippy::type_complexity)]
    const VECTORS: &[(usize, &str, &str, &str)] = &[
        (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26", "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
        (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b", "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
        (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63", "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a", "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6"),
        (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f", "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9", "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797"),
        (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b", "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae", "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3"),
        (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6", "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"),
        (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee", "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72", "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8"),
        (127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d", "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818", "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3"),
        (128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef", "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ec", "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca0225"),
        (129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12", "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f", "938d2d4435be30eafdbb2b7031f7857c98b04881227391dc40db3c7b21f41fc1"),
        (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e", "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"),
        (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4", "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"),
        (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444", "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69", "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"),
        (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1", "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"),
        (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030", "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5", "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273"),
        (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2", "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770", "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b"),
        (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3", "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a", "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081"),
        (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969", "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0", "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9"),
        (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995", "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc", "aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8"),
        (5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833", "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e20", "7a7acac8a02adcf3038d74cdd1d34527de8a0fcc0ee3399d1262397ce5817f60"),
        (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47", "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419", "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e"),
        (102_400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085", "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7", "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6"),
    ];

    #[test]
    fn matches_official_vectors_for_hash() {
        for &(len, want, _, _) in VECTORS {
            let got = hex(&hash(&test_input(len)));
            assert_eq!(got, want, "hash mismatch at input_len={len}");
        }
    }

    #[test]
    fn matches_official_vectors_for_keyed_hash() {
        for &(len, _, want, _) in VECTORS {
            let got = hex(&keyed_hash(TEST_KEY, &test_input(len)));
            assert_eq!(got, want, "keyed_hash mismatch at input_len={len}");
        }
    }

    #[test]
    fn matches_official_vectors_for_derive_key() {
        // The mode Shadowsocks-2022 actually uses. A wrong derive_key would
        // produce a key nothing else agrees with, and fail as an
        // authentication error rather than as anything pointing here.
        for &(len, _, _, want) in VECTORS {
            let got = hex(&derive_key(TEST_CONTEXT, &test_input(len)));
            assert_eq!(got, want, "derive_key mismatch at input_len={len}");
        }
    }

    #[test]
    fn empty_input_matches_the_published_constant() {
        // The single most-quoted BLAKE3 value; a sanity anchor independent of
        // the table above.
        assert_eq!(
            hex(&hash(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn crosses_the_chunk_boundary_correctly() {
        // 1023/1024/1025 exercise the last block of a chunk, an exactly-full
        // chunk, and the first two-chunk tree. An implementation that only
        // ever sees one chunk passes short tests and fails here.
        for &(len, want, _, _) in VECTORS.iter().filter(|v| v.0 >= 1023) {
            assert_eq!(hex(&hash(&test_input(len))), want, "input_len={len}");
        }
    }

    #[test]
    fn incremental_update_matches_one_shot() {
        // Chunking the input must not change the result, at any split point.
        let input = test_input(3000);
        let want = hash(&input);
        for split in [1usize, 63, 64, 65, 1023, 1024, 1025, 2048] {
            let mut h = Hasher::new();
            h.update(&input[..split]);
            h.update(&input[split..]);
            let mut got = [0u8; 32];
            h.finalize(&mut got);
            assert_eq!(got, want, "split at {split}");
        }
    }

    #[test]
    fn derive_key_is_domain_separated() {
        // Different contexts must produce different keys from identical
        // material, or the whole point of the KDF is lost.
        let material = b"shared secret";
        let a = derive_key("context A", material);
        let b = derive_key("context B", material);
        assert_ne!(a, b);
        // And it must differ from a plain hash of the same bytes.
        assert_ne!(a, hash(material));
    }

    #[test]
    fn keyed_hash_differs_from_unkeyed() {
        assert_ne!(keyed_hash(TEST_KEY, b"x"), hash(b"x"));
    }

    #[test]
    fn context_string_is_used_verbatim() {
        // Guards against accidentally trimming or re-encoding the context.
        assert_ne!(derive_key(TEST_CONTEXT, b"m"), derive_key(&format!("{TEST_CONTEXT} "), b"m"));
    }

    #[test]
    fn never_panics_on_any_input_shape() {
        let mut seed = 0x3141_5926_5358_9793u64;
        for _ in 0..300 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 5000) as usize;
            let input = test_input(len);
            let _ = hash(&input);
            let _ = derive_key("ctx", &input);
            let _ = keyed_hash(TEST_KEY, &input);
        }
    }
}
