-module(rfc3394).
-moduledoc """
Implementation of Advanced Encryption Standard (AES) Key Wrap Algorithm
as defined in https://datatracker.ietf.org/doc/html/rfc3394.html.
""".
-export([wrap/2, unwrap/2]).
-export([wrap/3, unwrap/3]).

%%% https://datatracker.ietf.org/doc/html/rfc3394.txt#section-2.2.3.1
-define(DEFAULT_IV, <<16#A6, 16#A6, 16#A6, 16#A6, 16#A6, 16#A6, 16#A6, 16#A6>>).

-doc """
wrap `KeyData` with `KEK` and default initial value (`IV`)

`KeyData` is a binary of at least 16 bytes,`byte_size(KeyData)`
must be divisible by 8.

`KEK` is a 128 bit or 192 bit or 256 bit AES key (binary).

the resulting `Ciphertext` 8 bytes larger than `KeyData`
""".
-spec wrap(KeyData :: binary(), KEK :: binary()) ->
	  Ciphertext :: binary().
wrap(KeyData, KEK) -> wrap(KeyData, KEK, ?DEFAULT_IV).

-doc """
unwrap `Ciphertext` with `KEK` and check `KeyData` integrity with default
initial value (`IV`)

`Ciphertext` is a binary of at least 24 bytes, `byte_size(Ciphertext)`
must be divisible by 8.

`KEK` is a 128 bit or 192 bit or 256 bit AES key (binary).

the resulting `KeyData` 8 smaller than `Ciphertext`

Will raise an exception of class `error` with reason `iv_mismatch` if the
integrity check fails.
""".
-spec unwrap(Ciphertext :: binary(), KEK :: binary()) ->
	  KeyData :: binary().
unwrap(Ciphertext, KEK) -> unwrap(Ciphertext, KEK, ?DEFAULT_IV).


-doc """
wrap `KeyData` with `KEK` and `IV`

`KeyData` is a binary of at least 16 bytes,`byte_size(KeyData)`
must be divisible by 8.

`KEK` is a 128 bit or 192 bit or 256 bit AES key (binary).

`IV` is a 8 byte binary.

the resulting `Ciphertext` 8 bytes larger than `KeyData`

see: https://datatracker.ietf.org/doc/html/rfc3394.txt#section-2.2.1
""".
-spec wrap(KeyData :: binary(), KEK :: binary(), IV :: binary()) ->
	  Ciphertext :: binary().
wrap(KeyData, KEK, <<A:64>>) when
      is_binary(KeyData), (byte_size(KeyData) rem 8) == 0,
      byte_size(KeyData) >= 16,
      is_binary(KEK),
      ((byte_size(KEK) == 16) orelse (byte_size(KEK) == 24)
       orelse (byte_size(KEK) == 32)) ->
    wrap1(lists:seq(0, 5), byte_size(KeyData) div 8, KEK, {A, KeyData}).

wrap1([], _N, _KEK, {A, R}) -> <<A:64, R/binary>>;
wrap1([J | T], N, KEK, {A, R}) ->
    wrap1(T, N, KEK, wrap2(lists:seq(1, N), J * N, KEK, {A, R})).

wrap2([], _JxN, _KEK, {A, R}) -> {A, R};
wrap2([I | T], JxN, KEK, {A, R}) ->
    <<S:((I - 1) * 8)/binary, Ri:8/binary, E/binary>> = R,
    <<B:64, Ro/binary>> =
	crypto:crypto_one_time(cipher(byte_size(KEK)), KEK,
			       <<A:64, Ri/binary>>, [{encrypt, true}]),
    wrap2(T, JxN, KEK, {B bxor (JxN + I), <<S/binary, Ro/binary, E/binary>>}).

-doc """
unwrap `Ciphertext` with `KEK` and check `KeyData` integrity with `IV`

`Ciphertext` is a binardf of at least 24 bytes, `byte_size(Ciphertext)`
must be divisible by 8.

`KEK` is a 128 bit or 192 bit or 256 bit AES key (binary).

`IV` is a 8 byte binary.

the resulting `KeyData` 8 smaller than `Ciphertext`

Will raise an exception of class `error` with reason `iv_mismatch` if the
integrity check fails.

see: https://datatracker.ietf.org/doc/html/rfc3394.txt#section-2.2.2 and
https://datatracker.ietf.org/doc/html/rfc3394.txt#section-2.2.3
""".
-spec unwrap(Ciphertext :: binary(), KEK :: binary(), IV :: binary()) ->
	  KeyData :: binary().
unwrap(<<A:64, _/binary>> = Ciphertext, KEK, IV) when
      (byte_size(Ciphertext) rem 8) == 0, byte_size(Ciphertext) >= 24,
      is_binary(IV), byte_size(IV) == 8, is_binary(KEK),
      ((byte_size(KEK) == 16) orelse (byte_size(KEK) == 24)
       orelse (byte_size(KEK) == 32)) ->
    N = (byte_size(Ciphertext) div 8) - 1,
    case unwrap1([5, 4, 3, 2, 1, 0], N, KEK, {A, Ciphertext}) of
	<<IV:(byte_size(IV))/binary, KeyData/binary>> -> KeyData;
	_ -> error(iv_mismatch) end.

unwrap1([], _N, _KEK, {A, <<_:8/binary, R/binary>>}) -> <<A:64, R/binary>>;
unwrap1([J | T], N, KEK, {A, R}) ->
    unwrap1(T, N, KEK, unwrap2(lists:seq(N, 1, -1), J * N, KEK, {A, R})).

unwrap2([], _JxN, _KEK, {A, R}) -> {A, R};
unwrap2([I | T], JxN, KEK, {A0, R}) ->
    <<S:(I * 8)/binary, Ri:8/binary, E/binary>> = R,
    <<A:64, Ro/binary>> =
	crypto:crypto_one_time(cipher(byte_size(KEK)), KEK,
			       <<(A0 bxor (JxN + I)):64, Ri/binary>>,
			       [{encrypt, false}]),
    unwrap2(T, JxN, KEK, {A, <<S/binary, Ro/binary, E/binary>>}).


cipher(16) -> aes_128_ecb;
cipher(24) -> aes_192_ecb;
cipher(32) -> aes_256_ecb.
