import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDnsStore } from "@/stores";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { DnsRecordRow } from "./DnsRecordRow";
import { DnsRecordForm } from "./DnsRecordForm";
import { Plus, Loader2, RefreshCw, ArrowUp, ArrowDown, ArrowUpDown, Search, Filter, X } from "lucide-react";
import { cn } from "@/lib/utils";
import type { DnsRecord } from "@/types";

type SortField = "type" | "name" | "value" | "ttl";
type SortDirection = "asc" | "desc" | null;

interface DnsRecordTableProps {
  accountId: string;
  domainId: string;
  supportsProxy: boolean;
}

export function DnsRecordTable({ accountId, domainId, supportsProxy }: DnsRecordTableProps) {
  const { t } = useTranslation();
  const { records, isLoading, isDeleting, fetchRecords, deleteRecord } =
    useDnsStore();
  const [showAddForm, setShowAddForm] = useState(false);
  const [editingRecord, setEditingRecord] = useState<DnsRecord | null>(null);
  const [deletingRecord, setDeletingRecord] = useState<DnsRecord | null>(null);
  const [sortField, setSortField] = useState<SortField | null>(null);
  const [sortDirection, setSortDirection] = useState<SortDirection>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);

  useEffect(() => {
    fetchRecords(accountId, domainId);
  }, [accountId, domainId, fetchRecords]);

  // 处理排序点击
  const handleSort = (field: SortField) => {
    if (sortField === field) {
      // 同一列：asc -> desc -> null 循环
      if (sortDirection === "asc") {
        setSortDirection("desc");
      } else if (sortDirection === "desc") {
        setSortDirection(null);
        setSortField(null);
      } else {
        setSortDirection("asc");
      }
    } else {
      // 新列：从 asc 开始
      setSortField(field);
      setSortDirection("asc");
    }
  };

  // 获取可用的记录类型
  const availableTypes = useMemo(() => {
    return [...new Set(records.map((r) => r.type))].sort();
  }, [records]);

  // 切换类型筛选
  const toggleType = (type: string) => {
    setSelectedTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  // 清除所有筛选
  const clearFilters = () => {
    setSearchQuery("");
    setSelectedTypes([]);
  };

  const hasActiveFilters = searchQuery || selectedTypes.length > 0;

  // 过滤和排序后的记录
  const filteredAndSortedRecords = useMemo(() => {
    let result = records;

    // 搜索过滤
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(
        (r) =>
          r.name.toLowerCase().includes(query) ||
          r.value.toLowerCase().includes(query)
      );
    }

    // 类型过滤
    if (selectedTypes.length > 0) {
      result = result.filter((r) => selectedTypes.includes(r.type));
    }

    // 排序
    if (!sortField || !sortDirection) return result;

    return [...result].sort((a, b) => {
      let aVal: string | number;
      let bVal: string | number;

      switch (sortField) {
        case "type":
          aVal = a.type;
          bVal = b.type;
          break;
        case "name":
          aVal = a.name;
          bVal = b.name;
          break;
        case "value":
          aVal = a.value;
          bVal = b.value;
          break;
        case "ttl":
          aVal = a.ttl;
          bVal = b.ttl;
          break;
        default:
          return 0;
      }

      if (typeof aVal === "number" && typeof bVal === "number") {
        return sortDirection === "asc" ? aVal - bVal : bVal - aVal;
      }

      const comparison = String(aVal).localeCompare(String(bVal));
      return sortDirection === "asc" ? comparison : -comparison;
    });
  }, [records, searchQuery, selectedTypes, sortField, sortDirection]);

  // 排序图标组件
  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) {
      return <ArrowUpDown className="h-3 w-3 ml-1 opacity-40" />;
    }
    if (sortDirection === "asc") {
      return <ArrowUp className="h-3 w-3 ml-1" />;
    }
    return <ArrowDown className="h-3 w-3 ml-1" />;
  };

  const handleDelete = (record: DnsRecord) => {
    setDeletingRecord(record);
  };

  const confirmDelete = async () => {
    if (!deletingRecord) return;
    await deleteRecord(accountId, deletingRecord.id, domainId);
    setDeletingRecord(null);
  };

  const handleEdit = (record: DnsRecord) => {
    setEditingRecord(record);
    setShowAddForm(true);
  };

  const handleFormClose = () => {
    setShowAddForm(false);
    setEditingRecord(null);
  };

  if (isLoading && records.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Toolbar */}
      <div className="flex flex-col gap-3 px-6 py-3 border-b bg-muted/30">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => fetchRecords(accountId, domainId)}
              disabled={isLoading}
            >
              <RefreshCw
                className={cn("h-4 w-4", isLoading && "animate-spin")}
              />
            </Button>
            <span className="text-sm text-muted-foreground">{t("common.total")}</span>
            <Badge variant="secondary">{records.length}</Badge>
            <span className="text-sm text-muted-foreground">{t("common.records")}</span>
            {hasActiveFilters && (
              <>
                <span className="text-sm text-muted-foreground">，{t("common.showing")}</span>
                <Badge variant="outline">{filteredAndSortedRecords.length}</Badge>
                <span className="text-sm text-muted-foreground">{t("common.records")}</span>
              </>
            )}
          </div>
          <Button size="sm" onClick={() => setShowAddForm(true)}>
            <Plus className="h-4 w-4 mr-2" />
            {t("dns.addRecord")}
          </Button>
        </div>

        {/* 搜索和筛选 */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t("dns.searchPlaceholder")}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 pl-8 pr-8"
            />
            {searchQuery && (
              <Button
                variant="ghost"
                size="icon"
                className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6"
                onClick={() => setSearchQuery("")}
              >
                <X className="h-3 w-3" />
              </Button>
            )}
          </div>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="h-8">
                <Filter className="h-4 w-4 mr-2" />
                {t("common.type")}
                {selectedTypes.length > 0 && (
                  <Badge variant="secondary" className="ml-2 h-5 px-1.5">
                    {selectedTypes.length}
                  </Badge>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              {availableTypes.map((type) => (
                <DropdownMenuCheckboxItem
                  key={type}
                  checked={selectedTypes.includes(type)}
                  onCheckedChange={() => toggleType(type)}
                >
                  {type}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>

          {hasActiveFilters && (
            <Button
              variant="ghost"
              size="sm"
              className="h-8"
              onClick={clearFilters}
            >
              <X className="h-4 w-4 mr-1" />
              {t("common.clearFilter")}
            </Button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 min-h-0 overflow-auto">
        <Table className="min-w-[700px]">
            <TableHeader className="sticky top-0 z-10 bg-background">
              <TableRow>
                <TableHead
                  className="w-24 cursor-pointer select-none hover:bg-muted/50"
                  onClick={() => handleSort("type")}
                >
                  <div className="flex items-center">
                    {t("common.type")}
                    <SortIcon field="type" />
                  </div>
                </TableHead>
                <TableHead
                  className="w-40 cursor-pointer select-none hover:bg-muted/50"
                  onClick={() => handleSort("name")}
                >
                  <div className="flex items-center">
                    {t("dns.name")}
                    <SortIcon field="name" />
                  </div>
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none hover:bg-muted/50"
                  onClick={() => handleSort("value")}
                >
                  <div className="flex items-center">
                    {t("dns.value")}
                    <SortIcon field="value" />
                  </div>
                </TableHead>
                <TableHead
                  className="w-24 cursor-pointer select-none hover:bg-muted/50"
                  onClick={() => handleSort("ttl")}
                >
                  <div className="flex items-center">
                    {t("dns.ttl")}
                    <SortIcon field="ttl" />
                  </div>
                </TableHead>
                {supportsProxy && <TableHead className="w-20">{t("dns.proxy")}</TableHead>}
                <TableHead className="w-24 text-right">{t("dns.actions")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAndSortedRecords.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={supportsProxy ? 6 : 5}
                    className="text-center text-muted-foreground py-8"
                  >
                    {hasActiveFilters ? t("common.noMatch") : t("dns.noRecords")}
                  </TableCell>
                </TableRow>
              ) : (
                filteredAndSortedRecords.map((record) => (
                  <DnsRecordRow
                    key={record.id}
                    record={record}
                    onEdit={() => handleEdit(record)}
                    onDelete={() => handleDelete(record)}
                    disabled={isDeleting}
                    showProxy={supportsProxy}
                  />
                ))
              )}
            </TableBody>
          </Table>
      </div>

      {/* Add/Edit Form Dialog */}
      {showAddForm && (
        <DnsRecordForm
          accountId={accountId}
          domainId={domainId}
          record={editingRecord}
          onClose={handleFormClose}
          supportsProxy={supportsProxy}
        />
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deletingRecord} onOpenChange={(open) => !open && setDeletingRecord(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("dns.deleteConfirm")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("dns.deleteConfirmDesc", { name: deletingRecord?.name })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {t("common.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
