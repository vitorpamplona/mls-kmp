# The mls-kmp guide

How to use mls-kmp, the Kotlin Multiplatform implementation of Messaging
Layer Security ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)), from
the first KeyPackage to a repaired fork. Read it in order the first time:
each chapter uses what the one before it set up.

1. [Getting started](getting-started.md): what MLS gives you, and the four objects you handle
2. [KeyPackages](key-packages.md): how others invite you
3. [Creating a group and adding members](groups.md)
4. [Joining from a Welcome](joining.md), including looking before you join
5. [Joining by external commit](external-joins.md), and resyncing
6. [Application messages](messages.md): encrypt, decrypt, authenticated data, late messages, exporters
7. [Processing incoming messages](processing.md): one entry point for everything
8. [Proposals and commits](proposals-and-commits.md): by reference, staged commits, custom proposals, wire formats
9. [Membership changes](membership.md): remove, update, leave, and capabilities
10. [Persistence](persistence.md): saving and restoring a group
11. [Your application's rules](application-rules.md): `MlsGroupPolicy`
12. [What mls-kmp validates, and what you must](validation.md)
13. [Following a group from a server](public-group.md): `PublicGroup`
14. [Fork recovery](fork-recovery.md)
15. [ReInit and branches](successor-groups.md)
16. [Security considerations](security.md)
17. [Upgrading](upgrading.md)

## The code in this guide runs

Every Kotlin block here is a region of
[`GuideSnippetsTest`](../../mls/src/commonTest/kotlin/com/vitorpamplona/mls/guide/GuideSnippetsTest.kt),
which runs on every target in every build, with assertions around each
region checking that it does what the text says. `GuideSnippetsSyncTest`
fails the build when a block here and its region differ. To change an
example, change the region and run

```
MLSKMP_UPDATE_GUIDE=1 ./gradlew :mls:jvmTest --rerun --tests com.vitorpamplona.mls.GuideSnippetsSyncTest
```

which copies every region into the pages.
