import { describe, it, expect, beforeEach } from 'vitest';
import {
  ProductAccountBindingStore,
  type ProductAccountBinding,
} from '../../src/heart/product-account-binding.js';

describe('ProductAccountBindingStore', () => {
  let store: ProductAccountBindingStore;

  beforeEach(() => {
    store = new ProductAccountBindingStore();
  });

  // ─── bind ────────────────────────────────────────────────────────────────

  it('binds an account to a Soma identity', () => {
    const binding = store.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6Mktest1',
      bindingType: 'primary',
    });

    expect(binding.accountId).toBe('acct-1');
    expect(binding.somaIdentityDid).toBe('did:key:z6Mktest1');
    expect(binding.bindingType).toBe('primary');
    expect(binding.boundAt).toBeGreaterThan(0);
    expect(binding.unboundAt).toBeNull();
  });

  it('accepts explicit timestamp', () => {
    const binding = store.bind(
      {
        accountId: 'acct-1',
        somaIdentityDid: 'did:key:z6Mktest1',
        bindingType: 'primary',
      },
      1000,
    );
    expect(binding.boundAt).toBe(1000);
  });

  it('rejects double-bind (1:1 invariant)', () => {
    store.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6Mktest1',
      bindingType: 'primary',
    });

    expect(() =>
      store.bind({
        accountId: 'acct-1',
        somaIdentityDid: 'did:key:z6Mktest2',
        bindingType: 'primary',
      }),
    ).toThrow('already bound');
  });

  it('allows binding after unbind', () => {
    store.bind(
      {
        accountId: 'acct-1',
        somaIdentityDid: 'did:key:z6Mktest1',
        bindingType: 'primary',
      },
      1000,
    );
    store.unbind('acct-1', 2000);

    const newBinding = store.bind(
      {
        accountId: 'acct-1',
        somaIdentityDid: 'did:key:z6Mktest2',
        bindingType: 'primary',
      },
      3000,
    );

    expect(newBinding.somaIdentityDid).toBe('did:key:z6Mktest2');
    expect(newBinding.boundAt).toBe(3000);
  });

  it('allows one identity to back multiple accounts', () => {
    store.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6Mkshared',
      bindingType: 'primary',
    });
    store.bind({
      accountId: 'acct-2',
      somaIdentityDid: 'did:key:z6Mkshared',
      bindingType: 'primary',
    });

    const byIdentity = store.getByIdentity('did:key:z6Mkshared');
    expect(byIdentity).toHaveLength(2);
  });

  it('returns a defensive copy from bind', () => {
    const binding = store.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6Mktest1',
      bindingType: 'primary',
    });
    (binding as any).accountId = 'mutated';
    expect(store.get('acct-1')!.accountId).toBe('acct-1');
  });

  // ─── get / getActive ─────────────────────────────────────────────────────

  it('returns undefined for unknown account', () => {
    expect(store.get('unknown')).toBeUndefined();
    expect(store.getActive('unknown')).toBeUndefined();
  });

  it('get returns unbound bindings, getActive does not', () => {
    store.bind(
      {
        accountId: 'acct-1',
        somaIdentityDid: 'did:key:z6Mktest1',
        bindingType: 'primary',
      },
      1000,
    );
    store.unbind('acct-1', 2000);

    expect(store.get('acct-1')).toBeDefined();
    expect(store.get('acct-1')!.unboundAt).toBe(2000);
    expect(store.getActive('acct-1')).toBeUndefined();
  });

  it('returns defensive copies from get', () => {
    store.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6Mktest1',
      bindingType: 'primary',
    });
    const a = store.get('acct-1')!;
    const b = store.get('acct-1')!;
    expect(a).not.toBe(b);
    expect(a).toEqual(b);
  });

  // ─── unbind ──────────────────────────────────────────────────────────────

  it('unbinds an active binding', () => {
    store.bind(
      {
        accountId: 'acct-1',
        somaIdentityDid: 'did:key:z6Mktest1',
        bindingType: 'primary',
      },
      1000,
    );

    expect(store.unbind('acct-1', 2000)).toBe(true);
    expect(store.get('acct-1')!.unboundAt).toBe(2000);
  });

  it('returns false for already-unbound account', () => {
    store.bind({ accountId: 'acct-1', somaIdentityDid: 'did:key:z6Mktest1', bindingType: 'primary' });
    store.unbind('acct-1');
    expect(store.unbind('acct-1')).toBe(false);
  });

  it('returns false for unknown account', () => {
    expect(store.unbind('unknown')).toBe(false);
  });

  // ─── rebind ──────────────────────────────────────────────────────────────

  it('atomically rebinds to a new identity', () => {
    store.bind(
      {
        accountId: 'acct-1',
        somaIdentityDid: 'did:key:z6Mkold',
        bindingType: 'primary',
      },
      1000,
    );

    const newBinding = store.rebind(
      'acct-1',
      'did:key:z6Mknew',
      'guardian-mediated',
      2000,
    );

    expect(newBinding.somaIdentityDid).toBe('did:key:z6Mknew');
    expect(newBinding.bindingType).toBe('guardian-mediated');
    expect(newBinding.boundAt).toBe(2000);

    // Old binding was dissolved
    const old = store.get('acct-1');
    // Store overwrites — only latest binding is visible
    expect(old!.somaIdentityDid).toBe('did:key:z6Mknew');
  });

  it('rebind works on an account with no prior binding', () => {
    const binding = store.rebind('acct-new', 'did:key:z6Mkfresh', 'primary', 1000);
    expect(binding.somaIdentityDid).toBe('did:key:z6Mkfresh');
    expect(store.activeCount).toBe(1);
  });

  // ─── getByIdentity ───────────────────────────────────────────────────────

  it('returns only active bindings for an identity', () => {
    store.bind({
      accountId: 'acct-1',
      somaIdentityDid: 'did:key:z6Mkshared',
      bindingType: 'primary',
    });
    store.bind({
      accountId: 'acct-2',
      somaIdentityDid: 'did:key:z6Mkshared',
      bindingType: 'delegated',
    });
    store.bind({
      accountId: 'acct-3',
      somaIdentityDid: 'did:key:z6Mkother',
      bindingType: 'primary',
    });

    store.unbind('acct-2');

    const bindings = store.getByIdentity('did:key:z6Mkshared');
    expect(bindings).toHaveLength(1);
    expect(bindings[0].accountId).toBe('acct-1');
  });

  it('returns empty array for unknown identity', () => {
    expect(store.getByIdentity('did:key:z6Mknobody')).toEqual([]);
  });

  // ─── size / activeCount / clear ──────────────────────────────────────────

  it('tracks size and activeCount correctly', () => {
    store.bind({ accountId: 'a', somaIdentityDid: 'did:key:z6Mk1', bindingType: 'primary' });
    store.bind({ accountId: 'b', somaIdentityDid: 'did:key:z6Mk2', bindingType: 'primary' });
    store.unbind('a');

    expect(store.size).toBe(2);
    expect(store.activeCount).toBe(1);
  });

  it('clear removes all bindings', () => {
    store.bind({ accountId: 'a', somaIdentityDid: 'did:key:z6Mk1', bindingType: 'primary' });
    store.clear();
    expect(store.size).toBe(0);
    expect(store.activeCount).toBe(0);
  });

  // ─── binding type variants ───────────────────────────────────────────────

  it('supports all binding types', () => {
    const types: Array<'primary' | 'delegated' | 'guardian-mediated'> = [
      'primary',
      'delegated',
      'guardian-mediated',
    ];
    for (const bt of types) {
      const s = new ProductAccountBindingStore();
      const b = s.bind({ accountId: 'acct', somaIdentityDid: 'did:key:z6Mk', bindingType: bt });
      expect(b.bindingType).toBe(bt);
    }
  });
});
