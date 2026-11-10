# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React, TypeScript and Vite, as specified in the user brief.

## Users

SOC L1 analysts operating a queue around the clock; administrators who manage action policy and integrations.

## Product Purpose

Process security alerts through investigation, evidence, verdict, permitted action, escalation and shift handover. The interface must display actual persisted backend state and expose only working operations.

## Operating Context

Splunk, TheHive and MISP integrations; a local demo mode with simulated external systems; a connected mode with read-only default; customer data separated by tenant.

## Capabilities and Constraints

Russian interface. Queue, alerts, investigation, evidence, timeline, playbooks, decisions, cases, exceptions, approved maintenance, integrations, SLA, shifts, reports, audit and settings. Analyst and admin roles. DEMO must be visibly identified. Empty and unknown monitoring states must remain distinguishable from healthy states.

## Brand Commitments

The name Sauyt.Lab and the report title «ОТЧЁТ — L1 ЦОК ТОО „Sauyt.Lab“ (передача смены)» come from the user brief. No logo or visual identity was supplied.

## Evidence on Hand

Only the user brief was supplied for this frontend. The sample shift report and historical PDF mentioned in the brief are absent from the workspace.

## Product Principles

- Put actionable queue state and investigation evidence before decoration.
- Keep simulated external actions and unknown health states explicit.
- Make status, verdict and approval separate concepts.
- Require a visible backend result before showing an action as successful.
