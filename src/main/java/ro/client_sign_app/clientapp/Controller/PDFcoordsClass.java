package ro.client_sign_app.clientapp.Controller;

public class PDFcoordsClass{
    double X;
    double Y;
    double width;
    double height;

    PDFcoordsClass(double X, double Y,double width, double height){
        this.X=X;
        this.Y=Y;
        this.width=width;
        this.height=height;
    }

    public double getX() {
        return X;
    }

    public double getY() {
        return Y;
    }

    public double getWidth() {
        return width;
    }

    public double getHeight() {
        return height;
    }
}
