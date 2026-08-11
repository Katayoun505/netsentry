import pandas as pd
import numpy as np
df = pd.read_csv('data/Wednesday_cleaned.csv')
numeric_cols = df.select_dtypes(include=[np.number]).columns
print('Any NaN remaining:', df[numeric_cols].isna().any().any())
print('Any inf remaining:', np.isinf(df[numeric_cols]).any().any())
print('Total rows:', len(df))
