#!/usr/bin/env python
# encoding: utf-8
import os

import pandas as pd


def main():
    reports_dir = "reports"
    all_data = []

    for unit_name in os.listdir(reports_dir):
        unit_path = os.path.join(reports_dir, unit_name)
        if os.path.isdir(unit_path):
            for file_name in os.listdir(unit_path):
                if file_name.endswith(".csv"):
                    file_path = os.path.join(unit_path, file_name)
                    df = pd.read_csv(file_path)
                    df["unit_name"] = unit_name
                    all_data.append(df)

    if all_data:
        final_df = pd.concat(all_data, ignore_index=True)
        final_df["risk_name_and_level"] = (
            final_df["risk_level"] + "-" + final_df["risk_name"]
        )
        print(final_df)

        # 根据unit_name,host列将risk_name列聚合
        aggregated_df = (
            final_df.groupby(["unit_name", "host"])["risk_name_and_level"]
            .agg(lambda x: ",".join(x))
            .reset_index()
        )
        print(aggregated_df)
        aggregated_df.to_csv("summary.csv")


if __name__ == "__main__":
    main()
