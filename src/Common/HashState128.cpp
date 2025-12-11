#include <Common/HashState128.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int NOT_IMPLEMENTED;
    extern const int MUST_BE_DECOMPRESSED_BEFORE_USE;
}

updateHashFast(const WriteBufferFromOwnString& buffer, HashState128& hash_state)
{
  hash_state.update(buffer.str().c_str(), buffer.str().size());
}

updateHashFast(const ColumnLowCardinality& column, HashState128& hash_state)
{
  updateHashFast(column.getIndexes(),                       hash_state);
  updateHashFast(column.getDictionary().getNestedColumn(),  hash_state);
}

updateHashFast(const ColumnLazy& column, HashState128& hash_state)
{
  throw Exception(ErrorCodes::NOT_IMPLEMENTED, "Method updateHashFast is not supported for {}", column.getName());
}

updateHashFast(const ColumnArray& column, HashState128& hash_state)
{
  updateHashFast(column.getOffsets(), hash_state);
  updateHashFast(column.getData(),    hash_state);
}

updateHashFast(const ColumnDecimal& column, HashState128& hash_state)
{
  const auto& data = column.getData();
  updateHashFast(data);
}

updateHashFast(const ColumnTuple& column, HashState128& hash_state)
{
  for (const auto& tuple_column : column.GetColumns())
  {
    updateHashFast(tuple_column, hash_state);
  }
}

updateHashFast(const ColumnDynamic& column, HashState128& hash_state)
{
  updateHashFast(column.getVariantColumn(), hash_state);
}

updateHashFast(const ColumnVector& column, HashState128& hash_state)
{
  const auto& data = column.getData();
  updateHashFast(data);
}

updateHashFast(const ColumnAggregateFunction& column, HashState128& hash_state)
{
  const auto& func = column.getAggregateFunction();
  const auto& data = column.getData();
  WriteBufferFromOwnString wbuf;
  func->serializeBatch(data, 0, data.size(), wbuf);
  updateHashFast(wbuf);
}

updateHashFast(const ColumnString& column, HashState128& hash_state)
{
  updateHashFast(column.getOffsets(), hash_state);
  updateHashFast(column.getChars(),   hash_state);
}

updateHashFast(const ColumnReplicated& column, HashState128& hash_state)
{
  throw Exception(ErrorCodes::NOT_IMPLEMENTED, "Method updateHashFast is not supported for {}", column.getName());
}

updateHashFast(const ColumnNullable& column, HashState128& hash_state)
{
  updateHashFast(column.getNullMapColumn(), hash_state);
  updateHashFast(column.getNestedColumn(),  hash_state);
}

updateHashFast(const ColumnObject& column, HashState128& hash_state)
{
  for (const auto& [_, wrapped_column] : column.getTypedPaths())
    updateHashFast(wrapped_column, hash_state);

  for (const auto& [_, wrapped_column] : colum.getDynamicPaths())
    updateHashFast(wrapped_column, hash_state);

  updateHashFast(column.getSharedDataColumn(), hash_state);
}

updateHashFast(const ColumnSparse& column, HashState128& hash_state)
{
  updateHashFast(column.getValuesColumn(),  hash_state);
  updateHashFast(column.getOffsetsColumn(), hash_state);
  updateHashFast(column.size(),             hash_state);
}

updateHashFast(const ColumnBLOB& column, HashState128& hash_state)
{
  throw Exception(ErrorCodes::NOT_IMPLEMENTED, "Method updateHashFast is not supported for {}", column.getName());
}

updateHashFast(const ColumnConst& column, HashState128& hash_state)
{
  updateHashFast(column.getDataColumn(), hash_state);
}

updateHashFast(const ColumnQBit& column, HashState128& hash_state)
{
  updateHashFast(column.getTupleColumn(), hash_state);
}

updateHashFast(const ColumnMap& column, HashState128& hash_state)
{
  updateHashFast(column.getNestedColumn(), hash_state);
}

updateHashFast(const ColumnCompressed& column, HashState128& hash_state)
{
  throw Exception(ErrorCodes::MUST_BE_DECOMPRESSED_BEFORE_USE, "Method updateHashFast is not supported for {}", column.getName());
}

updateHashFast(const ColumnVariant& column, HashState128& hash_state)
{
  updateHashFast(column.getLocalDiscriminatorsColumn(), hash_state);
  for (const auto& variant : column.getVariants())
  {
    updateHashFast(variant, hash_state);
  }
}

updateHashFast(const ColumnFixedString& column, HashState128& hash_state)
{
  updateHashFast(column.getN(),     hash_state);
  updateHashFast(column.getChars(), hash_state);
}

updateHashFast(const ColumnFunction& column, HashState128& hash_state)
{
  throw Exception(ErrorCodes::NOT_IMPLEMENTED, "Method updateHashFast is not supported for {}", column.getName());
}

}
