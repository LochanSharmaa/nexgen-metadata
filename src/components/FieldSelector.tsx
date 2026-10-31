import React, { useState, useMemo } from "react";
import { FIELD_DEFINITIONS } from "../types";

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
    <div className="flex flex-col h-full bg-white/80 backdrop-blur-md rounded-xl border border-amber-200 shadow-sm overflow-hidden">
      {/* Category Tabs & Search Bar */}
      <div className="p-3 border-b border-amber-200/60 bg-amber-50/50 flex flex-wrap gap-2 items-center justify-between">
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
                    ? "bg-yellow-200 text-slate-900 shadow-sm border border-yellow-300 font-bold"
                    : "bg-white text-stone-700 hover:bg-stone-50 border border-stone-200"
                }`}
              >
                <span>{icon}</span>
                <span>{cat}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                    isActive
                      ? "bg-yellow-100 text-amber-950 font-bold border border-amber-200/50"
                      : count === total
                      ? "bg-amber-100 text-amber-900 font-bold"
                      : "bg-stone-100 text-stone-600"
                  }`}
                >
                  {count}/{total}
                </span>
              </button>
            );
          })}
        </div>

        <div className="flex items-center space-x-2">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search 174+ fields..."
            className="px-3 py-1 bg-white border border-amber-200 rounded-lg text-xs placeholder-stone-400 focus:outline-none focus:ring-2 focus:ring-amber-400 w-48 shadow-inner"
          />
        </div>
      </div>

      {/* Bulk Select Subheader */}
      <div className="px-4 py-2 bg-stone-50/60 border-b border-amber-100 flex justify-between items-center text-xs">
        <span className="text-stone-600 font-medium">
          {search ? (
            <span>Found {filteredFields.length} matching fields</span>
          ) : (
            <span>
              Category: <strong className="text-stone-800">{activeCategory}</strong> ({activeCategorySelected}/{activeCategoryTotal} selected)
            </span>
          )}
        </span>
        <div className="space-x-3">
          <button
            onClick={() => onSelectCategory(activeCategory, true)}
            className="text-amber-800 hover:text-amber-950 font-bold hover:underline"
          >
            Select All
          </button>
          <span className="text-stone-300">|</span>
          <button
            onClick={() => onSelectCategory(activeCategory, false)}
            className="text-stone-500 hover:text-stone-800 font-medium hover:underline"
          >
            Deselect All
          </button>
        </div>
      </div>

      {/* Grid of Fields */}
      <div className="p-4 overflow-y-auto flex-1 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
        {filteredFields.map((field) => {
          const isSelected = selectedFields.has(field.key);
          return (
            <div
              key={field.key}
              onClick={() => onToggle(field.key)}
              className={`p-2.5 rounded-lg border text-xs cursor-pointer select-none transition-all flex items-start space-x-2.5 ${
                isSelected
                  ? "bg-yellow-50/70 border-amber-300 shadow-sm"
                  : "bg-white border-stone-200 hover:border-amber-200 hover:bg-stone-50/50"
              }`}
            >
              <div
                className={`w-4 h-4 rounded mt-0.5 flex items-center justify-center shrink-0 border ${
                  isSelected
                    ? "bg-yellow-200 border-amber-400 text-slate-900"
                    : "bg-white border-stone-300"
                }`}
              >
                {isSelected && <span className="text-[10px] font-bold">✓</span>}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span
                    className={`font-semibold truncate ${
                      isSelected ? "text-slate-900 font-bold" : "text-stone-800"
                    }`}
                  >
                    {field.label}
                  </span>
                </div>
                <p className="text-[11px] text-stone-500 line-clamp-1 mt-0.5">
                  {field.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Selection Status Footer */}
      <div className="p-2.5 bg-amber-50/40 border-t border-amber-200/50 flex justify-between items-center text-xs">
        <span className="text-stone-600">
          Total Selected: <strong className="text-amber-900">{totalSelectedCount}</strong> / {FIELD_DEFINITIONS.length} fields
        </span>
      </div>
    </div>
  );
};
