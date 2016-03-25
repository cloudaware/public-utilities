#!/usr/bin/python
import json, sys
with open(sys.argv[1]) as json_data:
  obj = json.load(json_data)
  ohai_keys = []
  for key in obj.iterkeys():
    if key.startswith('ohai_'):
      ohai_keys.append(key)
  for key in ohai_keys:
    del obj[key]
  if 'groups' in obj:
    del obj['groups']
  if 'group_names' in obj:
    del obj['group_names']
  json_data.close()
with open(sys.argv[1], "w") as json_data:
    json.dump(obj, json_data)
