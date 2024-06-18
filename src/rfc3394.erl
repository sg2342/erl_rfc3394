-module(rfc3394).

-export([wrap/2, unwrap/2]).
-export([wrap/3, unwrap/3]).

%%% https://datatracker.ietf.org/doc/html/rfc3394.txt#section-2.2.3.1
-define(DEFAULT_IV, <<16#A6, 16#A6, 16#A6, 16#A6, 16#A6, 16#A6, 16#A6, 16#A6>>).


-spec wrap(Plaintext :: binary(), KEK :: binary()) -> binary().
wrap(Plaintext, KEK) -> wrap(Plaintext, KEK, ?DEFAULT_IV).

-spec unwrap(Ciphertext :: binary(), KEK :: binary()) -> binary().
unwrap(Ciphertext, KEK) -> unwrap(Ciphertext, KEK, ?DEFAULT_IV).

%%% https://datatracker.ietf.org/doc/html/rfc3394.txt#section-2.2.1
-spec wrap(Plaintext :: binary(), KEK :: binary(), IV :: binary()) -> binary().
wrap(Plaintext, KEK, <<A:64>>) when
      is_binary(Plaintext), (byte_size(Plaintext) rem 8) == 0, is_binary(KEK),
      ((byte_size(KEK) == 16) orelse (byte_size(KEK) == 24)
       orelse (byte_size(KEK) == 32)) ->
    wrap1(lists:seq(0, 5), byte_size(Plaintext) div 8, KEK, {A, Plaintext}).

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


%%% https://datatracker.ietf.org/doc/html/rfc3394.txt#section-2.2.2
%%% and
%%% https://datatracker.ietf.org/doc/html/rfc3394.txt#section-2.2.3
-spec unwrap(Ciphertext :: binary(), KEK :: binary(), IV :: binary()) ->
	  binary().
unwrap(<<A:64, _/binary>> = Ciphertext, KEK, IV) when
      (byte_size(Ciphertext) rem 8) == 0,
      is_binary(IV), byte_size(IV) == 8, is_binary(KEK),
      ((byte_size(KEK) == 16) orelse (byte_size(KEK) == 24)
       orelse (byte_size(KEK) == 32)) ->
    N = (byte_size(Ciphertext) div 8) - 1,
    case unwrap1([5, 4, 3, 2, 1, 0], N, KEK, {A, Ciphertext}) of
	<<IV:(byte_size(IV))/binary, Plaintext/binary>> -> Plaintext;
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
