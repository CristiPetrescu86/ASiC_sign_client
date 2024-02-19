package ro.client_sign_app.clientapp.Controller;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import javax.swing.JFrame;
import javax.swing.JPanel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.rendering.PDFRenderer;

public class SignaturePanelExtractor extends JPanel{
    private BufferedImage image;
    private Rectangle2D.Double signaturePanelRect;
    private Point startPoint;
    private SignaturePanelCallback callback;

    public interface SignaturePanelCallback {
        void onSignaturePanelDrawn(Rectangle2D.Double rect);
    }

    public SignaturePanelExtractor(File file, SignaturePanelCallback callback) throws IOException {
        this.callback = callback;
        PDDocument document = PDDocument.load(file);
        PDFRenderer renderer = new PDFRenderer(document);
        PDPage page = document.getPage(0);
        int width = (int) page.getBBox().getWidth();
        int height = (int) page.getBBox().getHeight();
        image = renderer.renderImageWithDPI(0, 75);

        setPreferredSize(new Dimension(width, height));
        addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                startPoint = e.getPoint();
            }

            public void mouseReleased(MouseEvent e) {
                int x = Math.min(startPoint.x, e.getX());
                int y = Math.min(startPoint.y, e.getY());
                int w = Math.abs(startPoint.x - e.getX());
                int h = Math.abs(startPoint.y - e.getY());
                signaturePanelRect = new Rectangle2D.Double(x, y, w, h);
                repaint();
                if (callback != null) {
                    callback.onSignaturePanelDrawn(signaturePanelRect);
                }
            }
        });
    }

    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        g.drawImage(image, 0, 0, null);
        if (signaturePanelRect != null) {
            g.setColor(Color.RED);
            g.drawRect((int) signaturePanelRect.getMinX(), (int) signaturePanelRect.getMinY(), (int) signaturePanelRect.getWidth(), (int) signaturePanelRect.getHeight());
        }
    }

    public Rectangle2D.Double getSignaturePanelRect() {
        return signaturePanelRect;
    }
}
