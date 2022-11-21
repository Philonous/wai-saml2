-------------------------------------------------------------------------------
-- SAML2 Middleware for WAI                                                  --
-------------------------------------------------------------------------------
-- This source code is licensed under the MIT license found in the LICENSE   --
-- file in the root directory of this source tree.                           --
-------------------------------------------------------------------------------

-- | Defines types and functions for SP-initiated SSO. Use `issueAuthnRequest`
-- to initialise an `AuthnRequest` value which stores the parameters for the
-- authentication request you wish to issue to the IdP. You can update this
-- value as required. Then use `renderAuthnRequest` to format the
-- `AuthnRequest` as XML and render it to a `B.ByteString` containing a
-- base64-encoded representation of it. You should then perform a HTTP redirect
-- to send the client to the IdP, appending the base64-encoded `AuthnRequest`
-- as a query parameter named @SAMLRequest@. You may wish to read the
-- [SAML2 specification for this process](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html#5.1.2.SP-Initiated%20SSO:%20%20Redirect/POST%20Bindings|outline).
module Network.Wai.SAML2.Request (
    AuthnRequest(..),
    issueAuthnRequest,
    renderAuthnRequest
) where

-------------------------------------------------------------------------------

import Crypto.Random

import Data.Time.Clock
import Data.Time.Format

import Network.Wai.SAML2.XML

import Text.XML

import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

-------------------------------------------------------------------------------

-- | Parameters for SP-initiated SSO
data AuthnRequest
    -- Reference [AuthnRequest]
    = AuthnRequest {
        -- | The time at which 'AuthnRequest' was created.
        authnRequestTimestamp :: !UTCTime
        -- | Unique identifier for 'AuthnRequest' which should be preserved
        -- by the IdP in its response.
    ,   authnRequestID :: !T.Text
        -- | SP Entity ID
    ,   authnRequestIssuer :: !T.Text
        -- | Allow IdP to generate a new identifier
    ,   authnRequestAllowCreate :: !Bool
        -- | The URI reference corresponding to a name identifier format
    ,   authnRequestNameIDFormat :: !T.Text
    }
    deriving (Eq, Show)

-- | Creates a default 'AuthnRequest' with the current timestamp and a
-- randomly-generated ID.
issueAuthnRequest
    :: T.Text -- ^ SP Entity ID
    -> IO AuthnRequest
issueAuthnRequest authnRequestIssuer = do
    authnRequestTimestamp <- getCurrentTime
    -- Digits are not allowed in initial position
    -- Reference [ID Values]
    authnRequestID <- ("id" <>) . T.decodeUtf8 . Base16.encode <$> getRandomBytes 16
    pure AuthnRequest{
        authnRequestAllowCreate = True
    ,   authnRequestNameIDFormat =
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    ,   ..
    }

-- | Generates a base64-encoded `AuthnRequest` for SP initiated SSO, which
-- should be used as a query parameter named @SAMLRequest@.
renderAuthnRequest :: AuthnRequest -> B.ByteString
renderAuthnRequest AuthnRequest{..} =
    Base64.encode $
    BL.toStrict $
    renderLBS def $
    -- Reference [HTTP redirect binding]
    Document{
        documentPrologue = Prologue [] Nothing []
    ,   documentRoot = root
    ,   documentEpilogue = []
    }
    where
        timestamp = T.pack $
            formatTime defaultTimeLocale timeFormat authnRequestTimestamp
        root = Element
            (saml2pName "AuthnRequest")
            (Map.fromList
                [ ("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
                , ("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
                , ("ID", authnRequestID) -- Reference [RequestAbstractType] and see [ID Values]
                , ("Version", "2.0")  -- [RequestAbstractType]
                , ("IssueInstant", timestamp) -- [RequestAbstractType]
                , ("AssertionConsumerServiceIndex", "1") -- [AuthnRequest]
                ])
            [NodeElement issuer, NodeElement nameIdPolicy]
        -- Reference [RequestAbstractType]
        issuer = Element
            (saml2Name "Issuer")
            mempty
            [NodeContent authnRequestIssuer]
        -- Reference [AuthnRequest]
        nameIdPolicy = Element
            (saml2pName "NameIDPolicy")
            (Map.fromList
                [ ("allowCreate"
                    , if authnRequestAllowCreate then "true" else "false")
                , ("Format", authnRequestNameIDFormat)
                ])
            []

-------------------------------------------------------------------------------

-- Reference [RequestAbstractType]
-- Source: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=36
-- Section: 3.2.1 Complex Type RequestAbstractType

-- Reference [AuthnRequest]
-- Source: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=48
-- Section: 3.4.1 Element <AuthnRequest>

-- Reference [HTTP redirect binding]
-- Source:
-- https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf#page=15
-- Section: 3.4 HTTP Redirect Binding

-- Reference [ID Values]
-- Source: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=9
-- Section: 1.3.4 ID and ID Reference Values
-- Note: ID Values must conform to "xs:ID", which in turn has a restriction of "xs:NCName" (non-colonized name).
-- In practice that means they are a string consisting of
-- first 1 of: Letter or '_'
-- then 0 or more of: Letter, Digit, '.', '-', '_',  CombiningChar, Extender
--
-- Definitions of character classes: https://www.w3.org/TR/2000/WD-xml-2e-20000814#CharClasses
-- Compare e.g. https://stackoverflow.com/questions/1631396/what-is-an-xsncname-type-and-when-should-it-be-used
--and https://www.w3.org/TR/xmlschema-2/#dt-ccesN (see \i and \c, bute not that colons are excluded)
