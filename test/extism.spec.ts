import createPlugin from '@extism/extism';

(async function extismTest() {
  const plugin = await createPlugin('http://localhost:3001/count_vowels.wasm', {
    useWasi: true,
  });
  const out = await plugin.call('count_vowels', 'Hello, World!');
  console.log(out.text());
})();
