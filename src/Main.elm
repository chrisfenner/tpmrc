module Main exposing (main)

import Browser
import Html exposing (Html, Attribute, div, input, text)
import Html.Attributes exposing (..)
import Html.Events exposing (onInput)
import String exposing (toInt, fromInt)
import Result exposing (toMaybe, withDefault)
import Hex exposing (fromString, toString)
import Debug exposing (toString)
import Bitwise exposing (and, shiftRightBy)

-- MAIN
main =
  Browser.sandbox { init = init, update = update, view = view }

-- MODEL
type alias Model =
  { code : Int
  }

init : Model
init =
  { code = 0 }

-- UPDATE
type Msg =
  ChangeDec String
  | ChangeHex String

normalize : String -> String
normalize input =
  if String.isEmpty input then
 -- Interpret the empty string as a 0
    "0"
 -- Drop leading 0's
  else if String.startsWith "0" input then
    normalize (String.dropLeft 1 input)
 -- No valid TPM error is more than 4 digits, whether decimal or hex
  else if String.length input > 4 then
    String.left 4 input
  else
    input

update : Msg -> Model -> Model
update msg model =
  case msg of
    ChangeDec newCode ->
      { model | code = String.toInt (normalize newCode) |> Maybe.withDefault model.code }
    ChangeHex newCode ->
      { model | code = Hex.fromString (normalize newCode) |> Result.toMaybe |> Maybe.withDefault model.code }

-- VIEW
view : Model -> Html Msg
view model =
  div [ classList [
        ("decoder", True),
        ("success", model.code == 0),
        ("warning", isWarning(model.code)),
        ("error", isError(model.code))
      ]]
    [ div[] [ text "Dec:"
    , input [ placeholder "0"
            , value (String.fromInt model.code)
            , onInput ChangeDec
            ] [] ]
    , div[] [ text "Hex:"
    , input [ placeholder "0"
            , value (Hex.toString model.code)
            , onInput ChangeHex
            ] [] ]
    , div [] [ text (fmt (decode model.code)) ]
    ]

-- DECODING
type TpmRc = Fmt0 Fmt0Err | Fmt1 Fmt1Err

type alias Fmt0Err =
  { code : Int
  , vendor : Bool
  , warning : Bool
  }

type alias Fmt1Err =
  { code : Int
  , assoc : AssocType
  , assocNum : Int
  }

type AssocType = Handle | Parameter | Session

decode : Int -> TpmRc
decode code =
  let
    isType1 =
      (Bitwise.and code 0x80) /= 0
  in
  if isType1 then
    Fmt1 (decodeType1 code)
  else
    Fmt0 (decodeType0 code)

decodeType0 : Int -> Fmt0Err
decodeType0 raw =
  let
    code =
      (Bitwise.and raw 0x17f)
    vendor =
      (Bitwise.and raw 0x400) /= 0
    warning =
      (Bitwise.and raw 0x800) /= 0
  in
  { code = code, vendor = vendor, warning = warning }

decodeType1 : Int -> Fmt1Err
decodeType1 raw =
  let
    code =
      (Bitwise.and raw 0x3f)
    parameter =
      (Bitwise.and raw 0x40) /= 0
    paramNum =
      (Bitwise.shiftRightBy 8 (Bitwise.and raw 0xf00))
    session =
      if parameter then
        False
      else
        if paramNum >= 8 then
          True
        else
          False
    sessionNum =
      (paramNum - 8)
    handle =
      if parameter then
        False
      else
        not session
    handleNum =
      (Bitwise.and 0x7 paramNum)
    assoc =
      if parameter then
        Parameter
      else if session then
        Session
      else
        Handle
    assocNum =
      if parameter then
        paramNum
      else if session then
        sessionNum
      else
        handleNum
  in
  { code = code, assoc = assoc, assocNum = assocNum }

isWarning : Int -> Bool
isWarning code =
  let
      decoded = decode code
  in
  case decoded of
    Fmt0 rc0 ->
      rc0.warning
    _ ->
      False

isError : Int -> Bool
isError code =
  if code == 0 then
    False
  else
    not (isWarning code)

-- FORMATTING
fmt : TpmRc -> String
fmt rc =
  case rc of
    Fmt0 rc0 ->
      if rc0.warning then
        fmt0Warning rc0.code 
      else
        fmt0Name rc0.code
    Fmt1 rc1 ->
      (fmt1Name rc1.code) ++ " (" ++ (case rc1.assoc of
        Parameter -> "Parameter"
        Session -> "Session"
        Handle -> "Handle")
      ++ " " ++ (String.fromInt rc1.assocNum) ++ ")"

fmt0Name : Int -> String
fmt0Name code =
  case code of
    0 -> "TPM_RC_SUCCESS"
    0x1E -> "TPM_RC_BAD_TAG"
    0x100 -> "TPM_RC_INITIALIZE"
    0x101 -> "TPM_RC_FAILURE"
    0x103 -> "TPM_RC_SEQUENCE"
    0x10B -> "TPM_RC_PRIVATE"
    0x119 -> "TPM_RC_HMAC"
    0x120 -> "TPM_RC_DISABLED"
    0x121 -> "TPM_RC_EXCLUSIVE"
    0x124 -> "TPM_RC_AUTH_TYPE"
    0x125 -> "TPM_RC_AUTH_MISSING"
    0x126 -> "TPM_RC_POLICY"
    0x127 -> "TPM_RC_PCR"
    0x128 -> "TPM_RC_PCR_CHANGED"
    0x12D -> "TPM_RC_UPGRADE"
    0x12E -> "TPM_RC_TOO_MANY_CONTEXTS"
    0x12F -> "TPM_RC_AUTH_UNAVAILABLE"
    0x130 -> "TPM_RC_REBOOT"
    0x131 -> "TPM_RC_UNBALANCED"
    0x142 -> "TPM_RC_COMMAND_SIZE"
    0x143 -> "TPM_RC_COMMAND_CODE"
    0x144 -> "TPM_RC_AUTHSIZE"
    0x145 -> "TPM_RC_AUTH_CONTEXT"
    0x146 -> "TPM_RC_RANGE"
    0x147 -> "TPM_RC_NV_SIZE"
    0x148 -> "TPM_RC_NV_LOCKED"
    0x149 -> "TPM_RC_NV_AUTHORIZATION"
    0x14A -> "TPM_RC_NV_UNINITIALIZED"
    0x14B -> "TPM_RC_NV_SPACE"
    0x14C -> "TPM_RC_NV_DEFINED"
    0x150 -> "TPM_RC_BAD_CONTEXT"
    0x151 -> "TPM_RC_CPHASH"
    0x152 -> "TPM_RC_PARENT"
    0x153 -> "TPM_RC_NEEDS_TEST"
    0x154 -> "TPM_RC_NO_RESULT"
    0x155 -> "TPM_RC_SENSITIVE"
    _ -> "<unknown format-0 code 0x" ++ Hex.toString code ++ ">"

fmt1Name : Int -> String
fmt1Name code =
  case code of
     0x001 -> "TPM_RC_ASYMMETRIC"
     0x002 -> "TPM_RC_ATTRIBUTES"
     0x003 -> "TPM_RC_HASH"
     0x004 -> "TPM_RC_VALUE"
     0x005 -> "TPM_RC_HIERARCHY"
     0x007 -> "TPM_RC_KEY_SIZE"
     0x008 -> "TPM_RC_MGF"
     0x009 -> "TPM_RC_MODE"
     0x00A -> "TPM_RC_TYPE"
     0x00B -> "TPM_RC_HANDLE"
     0x00C -> "TPM_RC_KDF"
     0x00D -> "TPM_RC_RANGE"
     0x00E -> "TPM_RC_AUTH_FAIL"
     0x00F -> "TPM_RC_NONCE"
     0x010 -> "TPM_RC_PP"
     0x012 -> "TPM_RC_SCHEME"
     0x015 -> "TPM_RC_SIZE"
     0x016 -> "TPM_RC_SYMMETRIC"
     0x017 -> "TPM_RC_TAG"
     0x018 -> "TPM_RC_SELECTOR"
     0x01A -> "TPM_RC_INSUFFICIENT"
     0x01B -> "TPM_RC_SIGNATURE"
     0x01C -> "TPM_RC_KEY"
     0x01D -> "TPM_RC_POLICY_FAIL"
     0x01F -> "TPM_RC_INTEGRITY"
     0x020 -> "TPM_RC_TICKET"
     0x021 -> "TPM_RC_RESERVED_BITS"
     0x022 -> "TPM_RC_BAD_AUTH"
     0x023 -> "TPM_RC_EXPIRED"
     0x024 -> "TPM_RC_POLICY_CC"
     0x025 -> "TPM_RC_BINDING"
     0x026 -> "TPM_RC_CURVE"
     0x027 -> "TPM_RC_ECC_POINT"
     _ -> "<unknown format-1 code 0x" ++ Hex.toString code ++ ">"

fmt0Warning : Int -> String
fmt0Warning code =
  case code of
    0x101 -> "TPM_RC_CONTEXT_GAP"
    0x102 -> "TPM_RC_OBJECT_MEMORY"
    0x103 -> "TPM_RC_SESSION_MEMORY"
    0x104 -> "TPM_RC_MEMORY"
    0x105 -> "TPM_RC_SESSION_HANDLES"
    0x106 -> "TPM_RC_OBJECT_HANDLES"
    0x107 -> "TPM_RC_LOCALITY"
    0x108 -> "TPM_RC_YIELDED"
    0x109 -> "TPM_RC_CANCELED"
    0x10A -> "TPM_RC_TESTING"
    0x110 -> "TPM_RC_REFERENCE_H0"
    0x111 -> "TPM_RC_REFERENCE_H1"
    0x112 -> "TPM_RC_REFERENCE_H2"
    0x113 -> "TPM_RC_REFERENCE_H3"
    0x114 -> "TPM_RC_REFERENCE_H4"
    0x115 -> "TPM_RC_REFERENCE_H5"
    0x116 -> "TPM_RC_REFERENCE_H6"
    0x118 -> "TPM_RC_REFERENCE_S0"
    0x119 -> "TPM_RC_REFERENCE_S1"
    0x11A -> "TPM_RC_REFERENCE_S2"
    0x11B -> "TPM_RC_REFERENCE_S3"
    0x11C -> "TPM_RC_REFERENCE_S4"
    0x11D -> "TPM_RC_REFERENCE_S5"
    0x11E -> "TPM_RC_REFERENCE_S6"
    0x120 -> "TPM_RC_NV_RATE"
    0x121 -> "TPM_RC_LOCKOUT"
    0x122 -> "TPM_RC_RETRY"
    0x123 -> "TPM_RC_NV_UNAVAILABLE"
    _ -> "<unknown format-1 warning 0x" ++ Hex.toString (code + 0x900) ++ ">"

