-module(rfc3394_SUITE).
%%
%% KAT test vectors from
%% https://www.rfc-editor.org/rfc/rfc3394#section-4
%%

-export([init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2, all/0]).

-export([kat1/1, kat2/1, kat3/1, kat4/1, kat5/1, kat6/1, iv_mismatch/1]).

-include_lib("common_test/include/ct.hrl").

init_per_suite(Config) ->
    {ok, TVs} = file:consult(
                  filename:join(?config(data_dir, Config), "test_vectors")),
    [{tvs, TVs} | Config].

end_per_suite(_Config) -> ok.

init_per_testcase(_TestCase, Config) -> Config.

end_per_testcase(_TestCase, _Config) -> ok.

all() -> [kat1, kat2, kat3, kat4, kat5, kat6, iv_mismatch].

kat1(Config) -> kat(lists:nth(1, ?config(tvs, Config))).
kat2(Config) -> kat(lists:nth(2, ?config(tvs, Config))).
kat3(Config) -> kat(lists:nth(3, ?config(tvs, Config))).
kat4(Config) -> kat(lists:nth(4, ?config(tvs, Config))).
kat5(Config) -> kat(lists:nth(5, ?config(tvs, Config))).
kat6(Config) -> kat(lists:nth(6, ?config(tvs, Config))).

kat([Comment | L]) ->
    ct:comment(Comment),
    [KEK, KeyData, Ciphertext] =
	[binary:decode_hex(list_to_binary(V)) || V <- L],
    Ciphertext = rfc3394:wrap(KeyData, KEK),
    KeyData = rfc3394:unwrap(Ciphertext, KEK).

iv_mismatch(_Config) ->
    KEK = <<1:256>>,
    KeyData = <<2:256>>,
    Ciphertext = rfc3394:wrap(KeyData, KEK),
    {error, iv_mismatch} =
	try rfc3394:unwrap(Ciphertext, KEK, <<0:64>>)
	catch error:iv_mismatch -> {error, iv_mismatch} end.
