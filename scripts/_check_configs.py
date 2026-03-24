import yaml, os
for f in sorted(os.listdir('configs/defenders')):
    if any(x in f for x in ['ocsvm_', 'iforest_', 'lstm_ad_']):
        with open(f'configs/defenders/{f}') as fh:
            d = yaml.safe_load(fh)
        mp = d.get('model_path', 'null')
        print(f'{f}: model_path={mp}')
