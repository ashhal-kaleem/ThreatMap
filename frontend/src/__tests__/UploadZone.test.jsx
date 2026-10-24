import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import UploadZone from '../components/UploadZone';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const pdf = (size = 10) => new File([new Uint8Array(size)], 'report.pdf', { type: 'application/pdf' });

function setup(props = {}) {
  const onUploadSuccess = vi.fn();
  const utils = render(
    <UploadZone onUploadSuccess={onUploadSuccess} isUploading={false} setIsUploading={() => {}} maxUploadMb={1} {...props} />,
  );
  const input = utils.container.querySelector('input[type="file"]');
  return { onUploadSuccess, input };
}

describe('UploadZone', () => {
  it('rejects files over the configured limit without calling the API', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const { input } = setup();
    fireEvent.change(input, { target: { files: [pdf(2 * 1024 * 1024)] } });
    expect(screen.getByRole('alert').textContent).toMatch(/exceeds 1MB limit/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('shows the backend error when extraction failed despite HTTP 201', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ report_id: 'r1', status: 'failed' }), { status: 201 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ status: 'failed', current_step: 'failed', error_msg: 'Document contains no extractable text' }), {
          status: 200,
        }),
      );
    const { input, onUploadSuccess } = setup();
    fireEvent.change(input, { target: { files: [pdf()] } });
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/no extractable text/));
    expect(onUploadSuccess).not.toHaveBeenCalled();
  });

  it('shows the server detail on HTTP errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: 'Invalid file format: missing %PDF- magic bytes.' }), { status: 400 }),
    );
    const { input } = setup();
    fireEvent.change(input, { target: { files: [pdf()] } });
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/magic bytes/));
  });
});
