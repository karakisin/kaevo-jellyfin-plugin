"""Safety-first tooling for a physical Household Join fixture campaign.

This package is test-only.  It intentionally cannot issue Join API requests
and refuses live fixture writes when the deployed schema cannot provide an
exact, non-scan transaction discovery path.
"""
