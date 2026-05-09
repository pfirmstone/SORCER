# SORCER → JGDMS / DirtyChai Migration — Context Document

**Repository:** pfirmstone/SORCER  
**Companion repository:** pfirmstone/JGDMS (branch `trunk`)  
**Reference document:** `JGDMS/docs/Big picture security architecture/AI_Agent_JGDMS-GrantPermission-RoleManagement-context_8.md`  
**Status:** Planning / pre-implementation  

---

## 1. Purpose

This document captures the complete migration plan for updating SORCER to use the latest
JGDMS and DirtyChai features and to lock it down against Denial-of-Service (DoS) vectors.
It is intended to be handed to any developer or AI agent continuing this work, so that no
context from the prior assessment is lost.

The document covers two interleaved concerns:

1. **Architecture / security gaps** — what SORCER is missing relative to JGDMS v19 /
   DirtyChai, and the work required to fill each gap.
2. **`@AtomicSerial` serialisation requirement** — the specific rule that every
   SORCER class which holds a `java.util.Collection`, `List`, `Map`, or `Set` field and
   crosses a JERI wire **must** perform a defensive copy of that field in its
   `(GetArg)` constructor, because `AtomicInvocationDispatcher` replaces those types
   on the wire with immutable serialiser wrappers.

Both concerns are independent milestones that can progress in parallel once the build
target is updated.

---

## 2. Background — The Five-Layer Change

### 2.1 What JGDMS / DirtyChai Provides That SORCER Does Not Use

| Feature | JGDMS class / package | SORCER status |
|---|---|---|
| `@AtomicSerial` safe deserialization | `org.apache.river.api.io.AtomicSerial` | **Not used** — all wire classes use plain `Serializable` |
| `AtomicInvocationDispatcher` | `net.jini.jeri.AtomicInvocationDispatcher` | **Not used** — `SorcerILFactory` extends old River `BasicILFactory` |
| Three-layer policy stack | `DynamicPolicyProvider → RemotePolicyProvider → SpiffePolicyFile` | **Not used** — all policies grant `AllPermission` |
| `VerifyingProxyPreparer` | `net.jini.security.VerifyingProxyPreparer` | **Not used** — only `BasicProxyPreparer` |
| `SpiffeCredentialManager` | `net.jini.jeri.ssl.SpiffeCredentialManager` (JGDMS), `au.zeus.jdk.authorization.spire.SpiffeCredentialManager` (DirtyChai) | **Not present** — no SPIFFE workload identity |
| Wire DoS bounds | `BasicInvocationDispatcher.MAX_USER_PRINCIPALS = 64`, `MAX_STRING_BYTES = 8192` | **Not present** |
| JWT/OIDC user identity | `net.jini.security.jwt.JwtPrincipal`, `JwtLoginModule` | **Not present** |
| `Subject.callAs()` / `Subject.current()` | DirtyChai patched JDK (Java 21+) | **Not used** — `doAsPrivileged` used instead |
| Collection serialiser wrappers | `ListSerializer`, `MapSerializer`, `SetSerializer` | **Not handled** — no `(GetArg)` constructors |
| `Valid` defensive-copy helpers | `org.apache.river.api.io.Valid` | **Not present in SORCER** |

### 2.2 DoS Vectors Currently Open in SORCER

| Vector | Attack surface | Mitigation in JGDMS |
|---|---|---|
| Unlimited principal block in JERI wire | Any inbound RPC | `MAX_USER_PRINCIPALS = 64`, `MAX_STRING_BYTES = 8192` in `BasicInvocationDispatcher` |
| Arbitrary class loading from wire | `instantiatePrincipal()` with untrusted class name | Restricted to bootstrap + system classloader; unknown classes become `RemotePrincipal` placeholder |
| Blocking `<clinit>` in deserialized proxy JARs | `ProxyCodebaseSpi` / `PreferredClassLoader` | BAE + `VerdictRegistry.getVerdictByHash()` gate |
| `AllPermission` in every policy file | Java security manager is fully disabled | Three-layer policy stack with granular grants |
| Hash-collision DoS via `HashMap` / `HashSet` deserialization | Untrusted wire objects stored in hash collections | `AtomicMarshalInputStream` replaces with immutable `MapSerializer`/`SetSerializer` that do not call `hashCode`/`equals` on elements |
| Gadget-chain attacks via unchecked casts during deserialization | Plain `ObjectInputStream.readObject()` | `@AtomicSerial` validates invariants before object construction |

---

## 3. AtomicInvocationDispatcher and Collection Serialisers — The Core Rule

> **Every SORCER class that holds a `java.util.Collection`, `List`, `Set`, `SortedSet`,
> `Map`, or `SortedMap` field and is deserialized across a JERI wire via
> `AtomicInvocationDispatcher` MUST perform a defensive copy in its `(GetArg)` constructor.**

### 3.1 What the Dispatcher Does

`AtomicInvocationDispatcher` (in `net.jini.jeri`) overrides
`createMarshalInputStream()` and `createMarshalOutputStream()` to substitute
`AtomicMarshalInputStream` / `AtomicMarshalOutputStream` in place of the plain
River `MarshalInputStream` / `MarshalOutputStream`.

On the **output** (serialisation) side, `AtomicMarshalOutputStream` intercepts
all `List`, `Set`, `SortedSet`, `Map`, and `SortedMap` objects written to the
stream and substitutes immutable array-backed wrapper instances:

| Wire type written | Wrapper class |
|---|---|
| Any `List` or `Collection` | `org.apache.river.api.io.ListSerializer<T>` |
| Any `Set` or `SortedSet` | `org.apache.river.api.io.SetSerializer<T>` |
| Any `Map` or `SortedMap` | `org.apache.river.api.io.MapSerializer<K,V>` |

These wrappers implement `@AtomicSerial`, are immutable (all mutation methods
throw `UnsupportedOperationException`), and deliberately **do not call
`hashCode()` or `equals()` on their elements**, which prevents hash-collision
DoS attacks during deserialization.

On the **input** (deserialization) side, `AtomicMarshalInputStream` reconstructs
these wrapper instances via their `(GetArg)` constructors and delivers them to the
`@AtomicSerial` class being reconstructed via `GetArg.get(name, defaultValue, type)`.

### 3.2 What the Client Class Must Do

When `GetArg.get(fieldName, default, Collection.class)` (or `List.class`, `Map.class`,
etc.) returns a value, what is returned is a **serialiser wrapper, not the original
concrete type**. The Javadoc for `GetArg.get()` states explicitly:

> *"Instances of `java.util.Collection` will be replaced in the stream by a safe
> limited functionality immutable Collection instance that must be passed to a
> collection instance constructor."*

The `(GetArg)` constructor therefore **must not** store the value directly.
It must:

1. **Type-check every element** in the deserialized collection before populating the
   concrete collection.
2. **Defensive-copy** the contents into a new concrete collection (e.g., `ArrayList`,
   `ConcurrentHashMap`, `LinkedHashSet`) appropriate for the field.
3. Call the static check method **before** assigning any field — this is the
   `@AtomicSerial` rule that ensures atomic failure if invariants cannot be
   satisfied.

### 3.3 Required Pattern

The full `@AtomicSerial` pattern for a class with collection fields is:

```java
@AtomicSerial
public class MyMogram implements Serializable {

    // --- Serial form declaration ---
    private static final long serialVersionUID = 1L; // keep existing value — do NOT bump just for @AtomicSerial
    public static final ObjectStreamField[] serialPersistentFields = serialForm();

    public static SerialForm[] serialForm() {
        return new SerialForm[]{
            new SerialForm("name",    String.class),
            new SerialForm("mograms", List.class),   // interface type in serial form
            new SerialForm("data",    Map.class)     // interface type in serial form
        };
    }

    public static void serialize(PutArg arg, MyMogram m) throws IOException {
        arg.put("name",    m.name);
        arg.put("mograms", m.mograms);  // AtomicMarshalOutputStream replaces with ListSerializer
        arg.put("data",    m.data);     // AtomicMarshalOutputStream replaces with MapSerializer
        arg.writeArgs();
    }

    // --- Fields ---
    private final String name;
    private final List<Mogram> mograms;
    private final Map<String, Object> data;

    // --- @AtomicSerial constructor ---
    public MyMogram(GetArg arg) throws IOException, ClassNotFoundException {
        this(check(arg));
    }

    // Static check called BEFORE super() — ensures atomic failure
    private static GetArg check(GetArg arg) throws IOException, ClassNotFoundException {
        // 1. Type-check the name (non-collection field — straightforward)
        String name = arg.get("name", null, String.class);
        if (name == null) throw new InvalidObjectException("name must not be null");

        // 2. Retrieve the deserialized collection — arrives as ListSerializer
        List<Mogram> rawMograms = arg.get("mograms", Collections.emptyList(), List.class);

        // 3. Defensive copy with element type check using Valid.copyCol()
        //    Destination is the concrete type the field will actually use.
        List<Mogram> mograms = Valid.copyCol(rawMograms, new ArrayList<>(), Mogram.class);

        // 4. Retrieve the deserialized map — arrives as MapSerializer
        Map<String, Object> rawData = arg.get("data", Collections.emptyMap(), Map.class);

        // 5. Defensive copy of map entries with key and value type checks
        //    MapSerializer entries must be iterated and type-checked individually.
        Map<String, Object> data = new ConcurrentHashMap<>();
        for (Map.Entry<?, ?> entry : rawData.entrySet()) {
            if (!(entry.getKey() instanceof String))
                throw new InvalidObjectException("data map key must be String");
            // Value type check — adjust to expected concrete type if narrower
            Object v = entry.getValue(); // Object — caller validates on use
            data.put((String) entry.getKey(), v);
        }

        // Return arg so the delegating constructor can proceed
        return arg;
    }

    // Canonical private constructor — called after check() passes
    private MyMogram(GetArg arg, /* ignored, just forces check() */) throws IOException, ClassNotFoundException {
        this.name    = arg.get("name",    null, String.class);
        // Re-read and re-copy — check() already validated; this is the assignment pass
        List<Mogram> rawMograms = arg.get("mograms", Collections.emptyList(), List.class);
        this.mograms = Valid.copyCol(rawMograms, new ArrayList<>(), Mogram.class);
        Map<String, Object> rawData = arg.get("data", Collections.emptyMap(), Map.class);
        Map<String, Object> data = new ConcurrentHashMap<>();
        for (Map.Entry<?, ?> e : rawData.entrySet()) {
            data.put((String) e.getKey(), e.getValue());
        }
        this.data = data;
    }
}
```

> **Practical shortcut:** Because the static `check()` method and the delegating
> constructor share the same `GetArg` object, values retrieved in `check()` may
> be re-retrieved in the constructor body without re-reading the stream.
> `GetArg.get()` is idempotent with respect to the same field name.

### 3.4 `Valid` Helper Methods

`org.apache.river.api.io.Valid` provides the following helpers relevant to
SORCER's migration:

| Method | Use case |
|---|---|
| `Valid.copyCol(source, destination, elementType)` | Copy and type-check all elements of a `Collection` (any `List` or general `Collection`) |
| `Valid.copySet(source, destination, elementType, allowableHashCollisions)` | Copy and type-check all elements of a `Set`; also guards against hash-collision DoS |
| `Valid.copy(T[] array)` | Shallow-clone an array (prevents reference-steal of mutable arrays) |
| `Valid.deepCopy(T[] array)` | Deep-clone an array of `Cloneable` elements |
| `Valid.notNull(obj, message)` | Throws `InvalidObjectException` wrapping `NullPointerException` if `obj == null` |
| `Valid.nullElement(array, message)` | Throws if any element in the array is `null` |
| `Valid.isInstance(type, obj)` | Type-checks a single object; returns it cast or throws `InvalidObjectException` |

For `Map` fields, there is no single `Valid.copyMap()` helper — callers must
iterate the `MapSerializer` entry set and type-check keys and values individually
before inserting into a new concrete `Map`.

### 3.5 Why Direct Storage Is Unsafe

If a `(GetArg)` constructor stores the `ListSerializer`/`MapSerializer`/`SetSerializer`
reference directly into a field and later returns that object from a getter, an attacker
can retain a reference to the serialiser wrapper and call `equals()` or other methods
on elements (once those elements are in an attacker-controlled context).

More importantly, the serialiser wrappers are intended only for **transient use
during deserialization**. Storing them in long-lived object state:

* Violates the contract stated in `AtomicMarshalInputStream` and `GetArg` Javadoc.
* Defeats the DoS protection the serialiser wrappers provide.
* Breaks any code that assumes the field holds a mutable, concrete `List`/`Map`/`Set`.
* Will cause `UnsupportedOperationException` on any mutation attempt.

### 3.6 Shared Serial Form — Design Goal and Its Limitations

#### 3.6.1 The Design Goal: Zero Wire-Format Change

`@AtomicSerial` is explicitly designed to **share the same serial form as plain Java
Serialization**.  This is the primary migration enabler:

* `AtomicSerial.SerialForm` extends `ObjectStreamField` — the exact same class Java
  Serialization uses for `serialPersistentFields`.
* A class can declare:
  ```java
  private static final ObjectStreamField[] serialPersistentFields = serialForm();
  ```
  and both `ObjectInputStream` (plain Java Serialization) and `AtomicMarshalInputStream`
  (JGDMS) read the same named fields from the same wire bytes.
* **`serialVersionUID` must NOT be changed** solely because `@AtomicSerial` is being added.
  The serial form is identical; changing `serialVersionUID` would break compatibility with
  previously serialized instances for no reason.  Only change `serialVersionUID` when the
  serial form itself changes (fields added, removed, or renamed).

This means adding `@AtomicSerial` to a SORCER class, together with a `(GetArg)` constructor
that validates and defensively copies its fields, is a **backward-compatible operation**:
old serialized instances can still be read, and new instances can be read by old deserializers
that fall back to plain `ObjectInputStream`.

#### 3.6.2 When Shared Serial Form Is Not Possible

The shared-serial-form guarantee applies to the **outer class** annotated with `@AtomicSerial`.
It breaks down when a field's type does not implement `@AtomicSerial`.

`AtomicMarshalInputStream` is **not** a fallback to `ObjectInputStream.readObject()` for
non-`@AtomicSerial` types — it is more restrictive. The exact behavior for each field-type
category is:

| Situation | Effect |
|---|---|
| Field type is `@AtomicSerial` or `@AtomicExternal` | Constructed via `(GetArg)` / `readExternal()` constructor — fully safe |
| Field type is `Serializable` with **only primitive fields** in its entire hierarchy (no `readObject`, no `readObjectNoData`, no object fields anywhere in the hierarchy) | Instantiated and primitive fields populated directly — safe. No `DeSerializationPermission` required. |
| Field type is `Serializable` with **object fields** or a `readObject` / `readObjectNoData` method | **Rejected.** Under a `SecurityManager`: `AccessControlException` is thrown (`DeSerializationPermission` required). If `readObject` is found at any point: `InvalidObjectException("readObject method not supported")` is thrown. The outer `@AtomicSerial` class's `GetArg.get()` call fails. |
| Field type is a Java collection interface (`List`, `Map`, `Set`, `SortedSet`, `Map`, `SortedMap`) | `AtomicMarshalOutputStream` replaces it with a serialiser wrapper; `(GetArg)` receives a safe immutable wrapper — defensive copy required (see §3.2) |
| Field type is a JDK primitive, `String`, array of primitives | Safe — handled directly by the stream protocol |
| Field type is `Externalizable` (but not `@AtomicExternal`) | Allowed if the class holds `DeSerializationPermission("EXTERNALIZABLE")` — `readExternal()` is called on a freshly constructed instance |

> **Key consequence:** A non-`@AtomicSerial` `Serializable` class with object fields (e.g.
> `javax.security.auth.Subject`, `SorcerPrincipal`) **cannot be deserialized** by
> `AtomicMarshalInputStream`. The stream does not degrade gracefully — it throws an
> exception, preventing the outer class from being constructed at all.
> This is a migration blocker: all field types in an `@AtomicSerial` class's serial form
> must themselves be `@AtomicSerial`, primitive-only `Serializable`, or a supported
> collection/serialiser type.

#### 3.6.3 Implications for the SORCER Migration

Many SORCER wire classes hold fields of types that are outside SORCER's control and do
not currently implement `@AtomicSerial`:

| Common non-`@AtomicSerial` field type | Where it appears | Impact on migration |
|---|---|---|
| `net.jini.id.Uuid` | `ServiceMogram.mogramId`, `parentId`, `sessionId` | Check if `Uuid` has only primitive serial form — if so, safe. If not, **blocks migration**. |
| `javax.security.auth.Subject` | `ServiceMogram.subject`, `ServiceExertion.subject` | **Blocks migration** — `Subject` has `readObject()` and object fields; `AtomicMarshalInputStream` rejects it. Must be replaced with an `@AtomicSerial` wrapper or removed from the serial form. |
| `net.jini.core.transaction.Transaction` | `ServiceExertion.transaction` | Depends on implementation class — if not `@AtomicSerial` with object fields, **blocks migration**. |
| `sorcer.security.util.SorcerPrincipal` | Many exertion classes | **Blocks migration** if it has object fields or `readObject`. Must be converted to `@AtomicSerial`. |
| Various third-party `Serializable` entries stored in `ServiceContext<T>` | `ServiceContext.data` values | **Blocks migration** for any value type with object fields or `readObject`. `T` must be constrained to `@AtomicSerial` or primitive-only `Serializable` types. |

**Practical consequence:** Adding `@AtomicSerial` to `ServiceMogram` is NOT sufficient if
`Subject` is still in the serial form — deserialization of `ServiceMogram` itself will fail
when `AtomicMarshalInputStream` encounters the `Subject` field.

**Resolution strategy for non-`@AtomicSerial` field types:**

1. **Use `@AtomicSerial` `Serializer` wrappers from JGDMS** — JGDMS ships `@AtomicSerial`
   serializer implementations for several types (e.g. `X500PrincipalSerializer`,
   `AccessControlContextSerializer`, `PermissionSerializer`). Check whether a wrapper exists
   for the problematic type and use it in the serial form.

2. **Convert the field type to `@AtomicSerial`** — if the type is in SORCER's codebase
   (e.g. `SorcerPrincipal`), add `@AtomicSerial` support to it directly.

3. **Remove the field from the serial form** — if the field is not truly needed on the wire
   (e.g. `Subject` could be re-established from the JERI dispatch context via `ClientSubject`),
   remove it from `serialPersistentFields` / `serialForm()` and reconstruct it server-side.

4. **Change the field type in the serial form** — declare the serial form field as an
   `@AtomicSerial` replacement type, and convert in `serialize()` / `(GetArg)` constructor.

5. **Use `DeSerializationPermission`** to explicitly allow specific trusted `Serializable`
   classes that have only primitive fields — this is the no-migration path for classes that
   are genuinely primitive-only and therefore safe.

#### 3.6.4 Corrected `serialVersionUID` Guidance

The earlier guidance in this document (and in some code examples) to *"bump
`serialVersionUID` on first `@AtomicSerial` migration"* is **incorrect** for the common
case and has been superseded by this section.

| Scenario | Action |
|---|---|
| Adding `@AtomicSerial` to a class with **unchanged serial form** | **Do NOT change** `serialVersionUID`. |
| Changing the serial form (add/remove/rename a field) at the same time as adding `@AtomicSerial` | Change `serialVersionUID` — but only because of the serial form change, not because of `@AtomicSerial`. |
| Converting an existing `writeObject`/`readObject` class whose serialization differs from the declared field layout | May require a `serialVersionUID` change depending on whether the existing `serialVersionUID` is already explicit. |

In the code template in §3.3, remove the comment `// bump to 2L on first @AtomicSerial migration`
— it is misleading.  The `serialVersionUID` should remain whatever the class currently declares.

---

## 4. SORCER Classes Requiring `@AtomicSerial` and Defensive Copies

The following are the highest-priority classes that cross the JERI wire and hold
collection fields. They must be converted to `@AtomicSerial` before SORCER can work
with `AtomicInvocationDispatcher`.

### 4.1 Priority 1 — Most Frequently Serialized

| Class | Module | Collection fields | Notes |
|---|---|---|---|
| `ServiceMogram` | `sorcer-platform` | `Set<Principal>`, `List<...>` (inherited via `Subject`), projection fields | Abstract base — migration here propagates to all subtypes |
| `ServiceExertion` | `sorcer-platform` | `List<Signature>` (in fidelity), `List<ThrowableTrace>` | Sent on every `exert()` call |
| `ServiceContext<T>` | `sorcer-platform` | `ConcurrentHashMap<String,T> data`, `ReturnPath` | Core wire payload |
| `Task` | `sorcer-platform` | Inherits from `ServiceExertion`; `List<Signature>` fidelity | Elementary unit of work |
| `NetTask` | `sorcer-platform` | Inherits `Task`; adds `List<ServiceSignature>` | Network task |
| `CompoundExertion` | `sorcer-platform` | `List<Mogram> mograms` | Base of `Job` and `Block` |
| `Job` | `sorcer-platform` | `List<Mogram>` (from `CompoundExertion`), exception trace `List` | Composite job |

### 4.2 Priority 2 — Supporting Types

| Class | Module | Collection fields | Notes |
|---|---|---|---|
| `ServiceSignature` / `NetSignature` | `sorcer-platform` | `List<...>` fidelity entries | Carried inside every Task |
| `ControlContext` | `sorcer-platform` | `LinkedList<String>` execution path | Carried in every Exertion |
| `FidelityContext` | `sorcer-platform` | `Map<String, Fidelity>` | Governance context |
| `ServiceDeployment` | `sorcer-platform` | `List<String>` maintain nodes | Deployment descriptor |
| `ModelStrategy` | `sorcer-platform` | Various `Map` / `List` | Modeling strategy |
| `ContextNode` | `sorcer-platform` | `List<...>` child links | Context tree node |
| `Condition` | `sorcer-platform` | `List<String>` parameter paths | Conditional mogram |

### 4.3 Priority 3 — Entry/Tuple Classes

`Tuple2`, `Tuple3`, `Tuple4`, `Tuple5`, `Tuple6`, `FilterId`, `ExecPath`, `OutType`
in `sorcer.co.tuple` — these are smaller but still cross the wire. Some hold no
collection fields and just need the `@AtomicSerial` constructor scaffold; those with
array fields need `Valid.copy()` on the array.

### 4.4 Out of Scope for @AtomicSerial (No JERI Crossing)

`ScratchManagerSupport`, `ModelStrategy`, `BrowserModel`, `ContextGroovyObject`,
`ViewHolder` — these are server-side or UI-side objects that are not unmarshalled
over JERI and do not need `@AtomicSerial` immediately.

---

## 5. Full Architecture Migration Plan

The following phases are independent but ordered by dependency. Phases 1 and 2 can
begin in parallel.

### Phase 1 — Build Foundation (Blocker for Everything Else)

1. **Upgrade build tooling**
   - Gradle: 2.12 → 7.x+ (Java 21 module system support)
   - Java: 1.8 → 21 (DirtyChai JDK; `Subject.callAs()`, `ScopedValue`, virtual threads)
   - Replace `jdkName = '1.8'`, `languageLevel = '1.8'` in IntelliJ project settings

2. **Add JGDMS / DirtyChai Maven coordinates to `gradle/libraries.gradle`**
   - `jgdms-platform` — replaces `jsk-platform` / River for JERI core
   - `jgdms-jeri` — JERI with SPIFFE, JWT principal wire support, `AtomicInvocationDispatcher`
   - `jgdms-pref-class-loader` — `ProxyCodebaseSpi` with `VerdictRegistry` gate
   - `jgdms-policy` — three-layer policy stack
   - `jgdms-security-jwt` — `JwtPrincipal`, `JwtLoginModule`
   - Coordinate with DirtyChai JDK installation (or bootstrap-classpath mechanism)

3. **Fix `com.sun.jini.*` / `sun.*` import breakage** from Java 21 module restrictions
   - `ServiceProvider.java`: `com.sun.jini.config.Config` → JGDMS equivalent
   - `SorcerServiceDescriptor.java`: `com.sun.jini.start.*` → JGDMS equivalents

### Phase 2 — Security Policy Baseline

4. **Replace `AllPermission` in all policy files**
   - `bin/jini/policy/jini.policy` and all `bin/jini/scripts/services/*/` policy files
   - Adopt codebase-scoped grants using `httpmd:` URIs for each service JAR
   - `PolicyPermission("Remote")` and `GrantPermission` itself must **never** appear
     in delegatable grants
   - Stub SPIFFE principal grants can be added once Phase 4 (SPIRE deployment) is done

5. **Add `META-INF/PERMISSIONS.LIST` to each service JAR**
   - List only permissions the service actually needs (e.g., `SocketPermission`,
     `FilePermission` to specific scratch directories)
   - Avoids BAE flagging service JARs as `DANGEROUS` once SCAP pipeline is in place

### Phase 3 — Invocation Layer Modernisation

6. **Migrate `ServiceProvider.init()` to `Subject.callAs()`**

   Current (broken for DirtyChai v17+):
   ```java
   Subject.doAsPrivileged(loginContext.getSubject(),
       new PrivilegedExceptionAction() {
           public Object run() throws Exception { initAsSubject(); return null; }
       }, null);
   ```
   Target (aligned with `AbstractJiniService` pattern):
   ```java
   Subject.callAs(loginContext.getSubject(), () -> { initAsSubject(); return null; });
   ```

7. **Remove `ProviderDelegate.doMethodAs()` / replace with direct `checkPermission`**

   Current:
   ```java
   Subject.doAs(subject, new PrivilegedExceptionAction() {
       public Object run() throws Exception {
           AccessController.checkPermission(new AccessPermission(methodName));
           return null;
       }
   });
   ```
   Target: With DirtyChai, `AccessController.getContext()` automatically injects
   scoped user Subject principals into the domain array. The wrapper is no longer
   needed:
   ```java
   AccessController.checkPermission(new AccessPermission(methodName));
   ```

8. **Rebuild `SorcerILFactory` / `SorcerInvocationDispatcher` against JGDMS JERI**
   - `SorcerILFactory` must extend JGDMS `BasicILFactory` (not River)
   - `SorcerInvocationDispatcher` must extend `AtomicInvocationDispatcher` (or the
     JGDMS updated `BasicInvocationDispatcher`)
   - Wire DoS bounds (`MAX_USER_PRINCIPALS = 64`, `MAX_STRING_BYTES = 8192`) then
     apply automatically via the parent class
   - `RecordingInvocationDispatcher` analytics wrapper must stay in `invoke()` override,
     not `doInvoke()` — the Subject-scoped lambda wraps `doInvoke()` in JGDMS

9. **Retrieve `ClientSubject` / `ClientUserSubject` from dispatch context**

   Within `SorcerInvocationDispatcher.doInvoke()`:
   ```java
   ClientSubject cs = (ClientSubject)
       ServerContext.getServerContextElement(ClientSubject.class);
   Subject workerSubject = cs != null ? cs.getClientSubject() : null;

   ClientUserSubject cus = (ClientUserSubject)
       ServerContext.getServerContextElement(ClientUserSubject.class);
   Subject userSubject = cus != null ? cus.getUserSubject() : null;
   ```
   Use `workerSubject` (TLS-verified) and `userSubject` (wire-asserted, vouched for
   by workerSubject) for access control decisions, not `mogram.getSubject()` which
   is client-controlled data.

10. **Audit and fix executor/scheduler Subject propagation**

    `ServiceProvider.scheduler.schedule(callable, ...)` submissions do NOT propagate
    user Subject under DirtyChai's model (executor-submitted tasks do not inherit
    `SCOPED_SUBJECT`). Where the scheduled task needs user identity, capture before
    submission:
    ```java
    Subject[] subjects = Subject.currentAll();   // capture on the calling thread
    scheduler.schedule(() -> {
        // Pattern B — re-establish each Subject in reverse order
        Callable<Void> wrapped = () -> { task.run(); return null; };
        for (int i = subjects.length - 1; i >= 0; i--) {
            final Subject s = subjects[i];
            if (!(s instanceof WorkerSubject)) {
                final Callable<Void> prev = wrapped;
                wrapped = () -> Subject.callAs(s, prev);
            }
        }
        wrapped.call();
    }, delay, unit);
    ```

### Phase 4 — Identity Architecture

11. **Deploy SPIRE agents on each SORCER host**
    - Create SPIFFE trust domain, e.g., `spiffe://sorcer.example.org/`
    - Assign per-service SVIDs:
      - `spiffe://sorcer.example.org/sorcer/cataloger`
      - `spiffe://sorcer.example.org/sorcer/exertion-monitor`
      - `spiffe://sorcer.example.org/sorcer/space-worker`
      - `spiffe://sorcer.example.org/sorcer/logger`
      - `spiffe://sorcer.example.org/sorcer/policy` (for `InMemoryPolicyService`)
      - `spiffe://sorcer.example.org/admin/policy` (for djinn administrator)
      - `spiffe://sorcer.example.org/client/<id>` (for client nodes)

12. **Integrate JGDMS `SpiffeCredentialManager` into `ServiceProvider`**
    - When `loginContext == null` (SPIFFE path), `doStart()` runs directly
    - `WorkerSubject` is ambient in every `ProtectionDomain` — no `doAsPrivileged` needed
    - Outbound TLS calls use SPIFFE SVID credentials automatically via `SpiffeSubjectHolder`

13. **Replace `BasicProxyPreparer` with `VerifyingProxyPreparer`** in `SorcerServiceDescriptor`
    - Two-argument constructor `(contextElements, null)` for the advisory permissions path
    - Advisory path: soft failure — `PERMISSIONS.LIST` grants are applied, `UnsupportedOperationException` logged only
    - Explicit path: hard `SecurityException` on failure (use only for well-known services)

14. **Add JWT/OIDC user identity** (`JwtPrincipal`, `JwtLoginModule`)
    - Per-request `Subject.callAs(jwtUserSubject, ...)` in `SorcerInvocationDispatcher.doInvoke()`
    - Policy grants scoped to `JwtPrincipal "sub:alice@example.org"` + SPIFFE workload principal

### Phase 5 — `@AtomicSerial` Compliance

15. **Convert the Priority 1 classes** (§4.1) to `@AtomicSerial`
    - For each class: add `serialForm()`, `serialize()`, and `(GetArg)` constructor
    - In the `(GetArg)` constructor: call the static `check()` method before any field
      assignment; use `Valid.copyCol()` / `Valid.copySet()` / manual map iteration
      for all collection fields (see §3.3 pattern)
    - **Do NOT change `serialVersionUID`** unless the serial form itself is also changed
      (see §3.6.4); the `@AtomicSerial` annotation shares the same wire format as
      Java Serialization
    - For fields whose types do not implement `@AtomicSerial` AND have object fields or
      `readObject` (see §3.6.2): apply the resolution strategy in §3.6.3 — use JGDMS
      serializer wrappers, convert the type, remove from serial form, or change the declared
      type. These field types are migration **blockers**, not merely risks.

16. **Convert Priority 2 and Priority 3 classes** (§4.2, §4.3)

17. **Run BAE audit on all SORCER JARs** once the SCAP pipeline (Host 2) is reachable
    - Any class flagged `DANGEROUS` due to `BLOCKING_DECLARED` must have its `<clinit>`
      path reworked or its permission removed from `PERMISSIONS.LIST`

### Phase 6 — Three-Layer Policy Stack

18. **Deploy `InMemoryPolicyService`** for the SORCER djinn
    - Already implemented in JGDMS — deploy `ActivatableInMemoryPolicyServiceImpl`
    - Wire with `PolicyUpdateListener` for pull-on-notification to `RemotePolicyProvider`

19. **Transition static policy files → dynamic grants via `RemotePolicyProvider`**
    - Administrator (DirtyChai, SPIFFE `admin/policy` SVID) calls `replace(String[])` to
      update grants at runtime
    - Category grants and `GrantPermission` delegation ceiling managed here

20. **Wire `DynamicPolicyProvider → RemotePolicyProvider → SpiffePolicyFile`** stack
    in `SorcerServiceDescriptor` (replaces the current `new DynamicPolicyProvider(new PolicyFileProvider(...))`)

---

## 6. Key Design Decisions — Carried from JGDMS Context Document

| Decision | Rationale |
|---|---|
| Wire format for collection fields is immutable serialiser wrappers | Guards against hash-collision DoS; `hashCode`/`equals` not called on elements during deserialization |
| Defensive copy is the **client's** responsibility | Serialiser design separates safe transport from safe use; class author controls the concrete type |
| `Valid.copyCol(source, destination, elementType)` not `Collections.copy()` | `Valid.copyCol` adds type-checking via `Collections.checkedCollection()` before adding elements |
| For `Set` fields prefer `Valid.copySet(..., allowableHashCollisions)` | Explicitly bounds hash collisions; `allowableHashCollisions = 1` is safe for most cases |
| `MapSerializer` entries must be individually type-checked | `Valid` has no `copyMap()` — map key+value types require bespoke validation |
| `@AtomicSerial` check method called before `super()` | Ensures atomic failure — if invariants cannot be satisfied, no reference can be stolen |
| `serialVersionUID` unchanged when adding `@AtomicSerial` to an existing class | `@AtomicSerial` shares the same serial form as Java Serialization; changing `serialVersionUID` would needlessly break compatibility with existing serialized instances |
| `serialVersionUID` changed only when serial form changes | Bumping on a pure `@AtomicSerial` addition is incorrect; bump only when fields are added/removed/renamed alongside the migration |
| Fields of non-`@AtomicSerial` types are a **migration blocker** | `AtomicMarshalInputStream` does **not** fall back to `ObjectInputStream.readObject()`; non-`@AtomicSerial` types with object fields or `readObject` are **actively rejected** — they block deserialization of the outer class | Use JGDMS `@AtomicSerial` serializer wrappers, convert the type, remove from serial form, or replace with an `@AtomicSerial` equivalent (see §3.6.3) |
| Prefer JGDMS `@AtomicSerial` replacements for JDK/Jini types | Without replacements, any `Serializable` field type with object fields or `readObject` is rejected; JGDMS ships `@AtomicSerial` serializers for `AccessControlContext`, `Permission`, `X500Principal`, etc. | Check the `org.apache.river.api.io` package for available serializer wrappers before writing custom ones |
| `Subject.doAsPrivileged` → `Subject.callAs` for JAAS `LoginContext` path | DirtyChai v17+ rejects `WorkerSubject` in `doAs`; `callAs` binds to `SCOPED_SUBJECT` |
| `doMethodAs()` removed; direct `checkPermission` used | DirtyChai's `getContext()` injects scoped user Subject principals automatically |
| Executor-submitted tasks must capture and re-establish `Subject.currentAll()` | Executor tasks do not inherit `SCOPED_SUBJECT`; `new Thread()` inside `callAs` scope does (divergence from OpenJDK) |
| `AllPermission` → granular codebase-scoped grants | `AllPermission` disables the entire Java security model |
| `VerifyingProxyPreparer` advisory path for SORCER service proxies | Enforces three-way intersection without hard-failing on proxies whose `PERMISSIONS.LIST` is incomplete |
| SPIFFE SVIDs per service | Workload identity is ambient (`WorkerSubject` baked into `ProtectionDomain`) — no `doAs` for workload identity ever needed |
| JWT/OIDC for human user identity; Kerberos is legacy | JWT/OIDC is stateless; no KDC infrastructure required; integrates with `writeUserPrincipals()` wire protocol |

---

## 7. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| `@AtomicSerial` migration changes the serial form | If serial form fields are added/removed at the same time as adding `@AtomicSerial`, existing serialized instances are incompatible | Keep serial form identical on first migration pass; add/remove fields in a separate, explicitly versioned step |
| Non-`@AtomicSerial` field types are migration blockers | Any field type with object fields or `readObject` that doesn't implement `@AtomicSerial` causes deserialization of the outer `@AtomicSerial` class to fail entirely — not a silent degradation | Identify all such field types before starting migration; convert or replace each one using the strategy in §3.6.3 |
| DirtyChai replaces JDK classes (sealed `Subject` hierarchy) | Build and runtime must use DirtyChai JDK, not stock OpenJDK | Document JDK dependency in build; provide Docker/container image |
| Rio integration | Rio `ServiceDiscoveryManager` may not align with JGDMS `ProxyCodebaseSpi` VerdictRegistry gate | Assess Rio separately; potentially bypass VerdictRegistry gate for Rio-managed services initially |
| `ConcurrentHashMap` in `ServiceContext` — complex object graph | Hard to convert atomically without breaking the map's complex semantics | Convert in a dedicated PR; add extensive unit tests for round-trip serialization |
| `ServiceContext` generic type parameter `<T>` | `GetArg.get()` with `Class<T>` at erasure time | Use `Object.class` as type hint and cast; validate concrete type in check() method |

---

## 8. Files That Must Not Be Committed to `.github/agents/`

This document should reside in `docs/` only.  It must not be placed in `.github/agents/`
(those files contain instructions for other agents and are inaccessible to this agent).

---

*This document was generated from the results of a deep-dive code assessment of
`pfirmstone/SORCER` against `pfirmstone/JGDMS` (branch `trunk`) and the reference
document `AI_Agent_JGDMS-GrantPermission-RoleManagement-context_8.md`.*
