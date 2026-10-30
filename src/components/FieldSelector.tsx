import React, { useState, useMemo } from "react";
import { FIELD_DEFINITIONS, FieldDefinition } from "../types";

interface FieldSelectorProps {
  selectedFields: Set<string>;
  onToggle: (key: string) => void;
  onSelectCategory: (category: string, selected: boolean) => void;
}

const CATEGORY_ICONS: Record<string, string> = {
  "File System": "📁",
  "Hashes & Checksums": "🔒",
  "Image / EXIF": "📷",
  "Camera / Lens": "📸",
  "GPS / Location": "🌍",
  "Video": "🎬",
  "Audio": "🎵",
  "Documents": "📄",
  "PDF Specific": "📑",
  "Forensics / PE": "🔐",
};

export const FieldSelector: React.FC<FieldSelectorProps> = ({
  selectedFields,
  onToggle,
  onSelectCategory,
}) => {
  const [activeCategory, setActiveCategory] = useState<string>("File System");
  const [search, setSearch] = useState<string>("");

  const categories = useMemo(() => {
    const cats = new Set<string>();
    FIELD_DEFINITIONS.forEach((f) => cats.add(f.category));
    return Array.from(cats);
  }, []);

  const totalSelectedCount = useMemo(() => {
    return FIELD_DEFINITIONS.filter((f) => selectedFields.has(f.key)).length;
  }, [selectedFields]);

  const filteredFields = useMemo(() => {
    return FIELD_DEFINITIONS.filter((f) => {
      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          f.label.toLowerCase().includes(q) ||
          f.key.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q)
        );
      }
      return f.category === activeCategory;
    });
  }, [activeCategory, search]);

  const activeCategoryTotal = useMemo(() => {
    return FIELD_DEFINITIONS.filter((f) => f.category === activeCategory).length;
  }, [activeCategory]);

  const activeCategorySelected = useMemo(() => {
    return FIELD_DEFINITIONS.filter(
      (f) => f.category === activeCategory && selectedFields.has(f.key)
    ).length;
  }, [activeCategory, selectedFields]);

  return (
    <div className="flex flex-col h-full bg-white/70 backdrop-blur-md rounded-xl border border-purple-100 shadow-sm overflow-hidden">
      {/* Category Tabs & Search Bar */}
      <div className="p-3 border-b border-purple-100 bg-purple-50/50 flex flex-wrap gap-2 items-center justify-between">
        <div className="flex gap-1.5 overflow-x-auto py-1 max-w-[calc(100%-210px)] scrollbar-thin">
          {categories.map((cat) => {
            const catFields = FIELD_DEFINITIONS.filter((f) => f.category === cat);
            const total = catFields.length;
            const count = catFields.filter((f) => selectedFields.has(f.key)).length;
            const isActive = activeCategory === cat && !search;
            const icon = CATEGORY_ICONS[cat] || "📂";
            return (
              <button
                key={cat}
                onClick={() => {
                  setActiveCategory(cat);
                  setSearch("");
                }}
                className={`px-2.5 py-1 text-xs font-semibold rounded-lg transition-all whitespace-nowrap flex items-center gap-1.5 ${
                  isActive
                    ? "bg-[#630ed4] text-white shadow-sm"
                    : "bg-white text-gray-700 hover:bg-purple-100 border border-purple-100"
                }`}
              >
                <span>{icon}</span>
                <span>{cat}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                    isActive
                      ? "bg-white/20 text-white"
                      : count === total
                      ? "bg-purple-100 text-[#630ed4] font-bold"
                      : "bg-gray-100 text-gray-600"
                  }`}
                >
                  {count}/{total}
                </span>
              </button>
            );
          })}
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Search 174+ fields..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="text-xs px-3 py-1.5 rounded-lg border border-purple-200 focus:outline-none focus:ring-1 focus:ring-[#630ed4] bg-white w-44"
          />
        </div>
      </div>

      {/* Action Header */}
      <div className="px-4 py-2 bg-purple-50/30 border-b border-purple-100 flex justify-between items-center text-xs">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-gray-700">
            {search ? `Search Results (${filteredFields.length})` : `${CATEGORY_ICONS[activeCategory] || ""} ${activeCategory}`}
          </span>
          {!search && (
            <span className="text-[11px] text-purple-700 font-medium bg-purple-100/70 px-2 py-0.5 rounded-full">
              {activeCategorySelected}/{activeCategoryTotal} selected
            </span>
          )}
        </div>
        <div className="flex items-center space-x-3">
          <span className="text-gray-500 font-medium">
            Total: {totalSelectedCount}/{FIELD_DEFINITIONS.length}
          </span>
          <span>•</span>
          {!search ? (
            <>
              <button
                onClick={() => onSelectCategory(activeCategory, true)}
                className="text-[#630ed4] hover:underline font-medium"
              >
                Select Category
              </button>
              <span>•</span>
              <button
                onClick={() => onSelectCategory(activeCategory, false)}
                className="text-gray-500 hover:underline font-medium"
              >
                Clear Category
              </button>
            </>
          ) : (
            <button
              onClick={() => {
                filteredFields.forEach((f) => {
                  if (!selectedFields.has(f.key)) onToggle(f.key);
                });
              }}
              className="text-[#630ed4] hover:underline font-medium"
            >
              Select All Matches
            </button>
          )}
        </div>
      </div>

      {/* Checkbox Grid (2 columns) */}
      <div className="p-4 overflow-y-auto grid grid-cols-2 gap-2 flex-1">
        {filteredFields.map((field) => {
          const checked = selectedFields.has(field.key);
          return (
            <label
              key={field.key}
              title={field.description}
              className={`flex items-start p-2 rounded-lg border text-xs cursor-pointer select-none transition-all ${
                checked
                  ? "bg-purple-50/70 border-purple-300 shadow-sm"
                  : "bg-white border-gray-200 hover:border-purple-200"
              }`}
            >
              <input
                type="checkbox"
                checked={checked}
                onChange={() => onToggle(field.key)}
                className="mt-0.5 rounded text-[#630ed4] focus:ring-[#630ed4] mr-2"
              />
              <div className="flex-1 overflow-hidden">
                <div className="font-semibold text-gray-800 truncate">
                  {field.label}
                </div>
                <div className="text-[10px] text-gray-500 truncate">
                  {field.description}
                </div>
              </div>
            </label>
          );
        })}
      </div>
    </div>
  );
};
