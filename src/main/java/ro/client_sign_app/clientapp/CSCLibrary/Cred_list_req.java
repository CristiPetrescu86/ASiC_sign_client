package ro.client_sign_app.clientapp.CSCLibrary;

public class Cred_list_req {
    private Integer maxResults;

    public Cred_list_req(Integer maxResults) {
        this.maxResults = maxResults;
    }

    public Integer getMaxResults() {
        return maxResults;
    }

    public void setMaxResults(Integer maxResults) {
        this.maxResults = maxResults;
    }
}
