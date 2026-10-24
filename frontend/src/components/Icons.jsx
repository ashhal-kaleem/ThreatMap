// Small inline SVG icon set (stroke icons, inherit currentColor).
const base = {
  width: 18,
  height: 18,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
  focusable: false,
};

const make = (paths) =>
  function Icon({ size = 18, className }) {
    return (
      <svg {...base} width={size} height={size} className={className}>
        {paths}
      </svg>
    );
  };

export const FileIcon = make(
  <>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5M9 13h6M9 17h4" />
  </>,
);
export const UploadIcon = make(
  <>
    <path d="M12 16V4M7 9l5-5 5 5" />
    <path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" />
  </>,
);
export const SearchIcon = make(
  <>
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.5-3.5" />
  </>,
);
export const CopyIcon = make(
  <>
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M5 15V5a2 2 0 0 1 2-2h10" />
  </>,
);
export const CheckIcon = make(<path d="M5 12.5 10 17 19 7" />);
export const AlertIcon = make(
  <>
    <path d="M12 3 2 20h20z" />
    <path d="M12 10v4M12 17h.01" />
  </>,
);
export const DownloadIcon = make(
  <>
    <path d="M12 4v12M7 11l5 5 5-5" />
    <path d="M4 20h16" />
  </>,
);
export const ChevronIcon = make(<path d="m9 6 6 6-6 6" />);
export const RefreshIcon = make(
  <>
    <path d="M20 11a8 8 0 0 0-14.9-3M4 4v4h4" />
    <path d="M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4" />
  </>,
);
export const ShieldIcon = make(<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z" />);
