"""Factory creating reporter instances by output format name."""

from typing import ClassVar

from xsslab.reporters.base import BaseReporter
from xsslab.reporters.json_reporter import JSONReporter
from xsslab.reporters.markdown_reporter import MarkdownReporter
from xsslab.reporters.sarif_reporter import SARIFReporter


class ReporterFactory:
    """Factory creating reporters for supported export formats."""

    _REPORTERS: ClassVar[dict[str, type[BaseReporter]]] = {
        "json": JSONReporter,
        "markdown": MarkdownReporter,
        "md": MarkdownReporter,
        "sarif": SARIFReporter,
    }

    @classmethod
    def create_reporter(cls, format_name: str) -> BaseReporter:
        """Instantiate the matching reporter for the requested format.

        Args:
            format_name: Name of format ('json', 'markdown', 'md', 'sarif')

        Raises:
            ValueError: If unsupported format is requested.
        """
        fmt = format_name.lower().strip()
        reporter_cls = cls._REPORTERS.get(fmt)
        if not reporter_cls:
            available = ", ".join(cls._REPORTERS.keys())
            raise ValueError(f"Unsupported report format '{format_name}'. Supported: {available}")
        return reporter_cls()
