# Getting Started with SAML 2.0

This repo contains the websites used for the two demos in my Pluralsight course "[Getting Started with SAML 2.0](https://www.scottbrady91.com/SAML/New-Pluralsight-Course-Getting-Started-with-SAML-20)".

It contains:

- a SAML Identity Provider using Rsk.Saml and IdentityServer4
- two SAML Service Providers using Rsk.Saml

Rsk.Saml is a licensed component. You can get a 30-day demo license from [identityserver.com](https://www.identityserver.com/products/saml2p). This license must be added to `Common.DemoLicense` for these demos to work.

To run this demo against Okta, you will need to sign up for an Okta account, and replace the call to `AddSaml2p` in `sp.Startup` with the commented out code and your Okta configuration.
