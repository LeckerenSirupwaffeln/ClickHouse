#include <Common/HashState128.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int NOT_IMPLEMENTED;
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

}
