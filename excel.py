import datetime
import logging
from pandas import DataFrame, ExcelWriter

logger = logging.getLogger(__name__)

def generate_excel(resources):
    create_date = datetime.datetime.now()
    
    file_name = f"Inventory-{create_date.day}-{create_date.month}-{create_date.year}.xlsx"

    writer = ExcelWriter(file_name, engine='xlsxwriter')

    logger.info("==========Generating Excel==========")

    for key in resources:
        df = DataFrame(resources[key])
        df.to_excel(writer, sheet_name=key.upper(), index=False)
        for i, col in enumerate(df.columns):
            column_len = df[col].astype(str).str.len().max()
            column_len = max(column_len, len(col)) + 2
            for column in df:
                # Columns that need to wrap text
                if column == 'Source Ranges':
                    workbook = writer.book
                    worksheet = writer.sheets[key.upper()]
                    format_sheet = workbook.add_format({'text_wrap': True})
                    worksheet.set_column('F:F', column_len + 25, format_sheet)
                else:
                    worksheet = writer.sheets[key.upper()]
                    worksheet.set_column(i, i, column_len)

    writer.save()

    logger.info(f"=========={file_name} ready==========")
