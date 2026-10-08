import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';

const collector=new URL('../scripts/discover_overture.py',import.meta.url);
const source=readFileSync(collector,'utf8');
test('official data collector is geographically capped, source-restricted, and never visits candidate websites',()=>{
  assert.match(source,/stac\.overturemaps\.org\/catalog\.json/);
  assert.match(source,/overturemaps-us-west-2/);
  assert.match(source,/choices=\(10, 20, 25\)/);
  assert.match(source,/bbox\.xmin BETWEEN/);
  assert.match(source,/bbox\.ymin BETWEEN/);
  assert.match(source,/taxonomy\.primary IN/);
  assert.match(source,/OVERTURE_PUBLIC/);
  assert.doesNotMatch(source,/subprocess|playwright|selenium|exec\(|POST\s+https/i);
  const help=spawnSync('python3',[collector.pathname,'--help'],{encoding:'utf8',timeout:4000});
  assert.equal(help.status,0,help.stderr);
  assert.match(help.stdout,/--area/);
  assert.match(help.stdout,/--limit/);
});
